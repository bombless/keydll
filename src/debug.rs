use libloading::{Library, Symbol};
use std::ffi::CString;
use std::os::raw::c_int;
use iced_x86::{Decoder, DecoderOptions, Formatter, Mnemonic, NasmFormatter};
use std::slice;
use std::io::stdin;
use windows::Win32::System::Memory::{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE
};
use windows::Win32::Foundation::GetLastError;
use std::mem;


// 定义与 C 函数匹配的类型
type DataEncryptC1 = unsafe extern "stdcall" fn(
    *const std::os::raw::c_char,
    *const std::os::raw::c_char,
    *mut std::os::raw::c_char,
    c_int
) -> c_int;

unsafe fn slice_of<'a>(actual_address: u64) -> &'a [u8] {
    unsafe {
        slice::from_raw_parts(actual_address as _, 512)
    }
}

unsafe fn slice_of_ip<'a>(ip: u64, offset: u64, len: usize) -> &'a [u8] {
    unsafe {
        slice::from_raw_parts((ip + offset) as *const u8, len)
    }
}

fn alloc_and_patch(address: *const u8, len: usize) -> Result<*mut u8, String> {
    let allocation_size = len.checked_add(1).ok_or("len too large")?;

    let new_code = unsafe {
        VirtualAlloc(
            None,
            allocation_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if new_code.is_null() {
        unsafe {
            let error = GetLastError();
            return Err(format!("VirtualAlloc failed with error: {}", error.0));
        }
    }

    unsafe {
        std::ptr::copy_nonoverlapping(address, new_code.cast(), len);
        *new_code.cast::<u8>().add(len) = 0xc3;
    }

    Ok(new_code.cast())
}

unsafe fn detect(actual_address: u64, rva_address: u64) -> Vec<u64> {
    let mut decoder = Decoder::with_ip(32, unsafe { slice_of(actual_address) }, rva_address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();

    let mut ret = Vec::new();

    for instruction in decoder.iter() {
        // 反汇编当前指令
        let mut output = String::new();
        formatter.format(&instruction, &mut output);
        let bytes = unsafe { slice_of_ip(instruction.ip(), actual_address - rva_address, instruction.len()) };
        let bytes_string = format!("{bytes:X?}");
        println!("{:08X} {bytes_string:>32} {}", instruction.ip(), output);

        // 检查是否是无条件跳转（JMP）
        if instruction.mnemonic() == Mnemonic::Jmp {
            // println!("{instruction:?}");
            println!("==================\n You jump, I jump. \n==================");
            let add = instruction.ip_rel_memory_address();
            let offset = add - rva_address;
            let mut decoder_jumped = Decoder::with_ip(32, unsafe { slice_of(actual_address + offset) }, add, DecoderOptions::NONE);
            for instruction in decoder_jumped.iter() {
                let mut output = String::new();
                formatter.format(&instruction, &mut output);
                let bytes = unsafe { slice_of_ip(instruction.ip(), actual_address - rva_address, instruction.len()) };
                let bytes_string = format!("{bytes:X?}");
                println!("{:08X} {bytes_string:>32} {}", instruction.ip(), output);
                if instruction.mnemonic() == Mnemonic::Ret {
                    break;
                }
            }
            break;
        }

        // 可选：检查其他终止条件（如 RET、INT3）
        match instruction.mnemonic() {
            Mnemonic::Ret | Mnemonic::Int3 => {
                println!("Found RET/INT3, stopping.");
                break;
            }
            _ => {}
        }

        if instruction.mnemonic() == Mnemonic::Call {
            let addr = instruction.ip_rel_memory_address();
            println!("function call to {:08X} at {:08X}", addr, instruction.ip());
            if addr == 0x0045b9e0 {
                println!("此处调用DataEncrypt，真实地址{:08X}", actual_address - rva_address + instruction.ip());
                println!("actual_address ({actual_address:08X}) - rva_address ({rva_address:08X}) + instruction.ip() ({:08X})", instruction.ip());
                println!("{}", actual_address - rva_address + instruction.ip() == instruction.ip());
            }
            ret.push(addr);
        }
    }
    ret
}

fn main() {
    // 输入数据和密钥
    let in_data = "D47240002000A00A";
    let key = "B48AFD20C61FBFDB";

    println!("参数1：{}", in_data);
    println!("参数2：{}", key);

    // 转换为 C 字符串
    let c_in_data = CString::new(in_data).expect("Failed to create CString");
    let c_key = CString::new(key).expect("Failed to create CString");

    // 输出缓冲区
    let out_buffer_size = 1024;
    let mut out_buffer = vec![0u8; out_buffer_size];

    unsafe {
        // 加载 DLL
        let lib = Library::new("Keydll.dll").expect("Failed to load DLL");

        // 获取函数指针
        let func: Symbol<DataEncryptC1> = lib.get(b"DataEncrypt_C1")
            .expect("Failed to get function");

        let func_ptr = func.clone().try_as_raw_ptr().unwrap() as *const u8;


        const BASE : u64 = 0x45bc84;
        
        let rva_offset = func_ptr as u64 - BASE;
        println!("address： {:08X}", func_ptr as usize);

        // 调用函数
        let result = func(
            c_in_data.as_ptr(),
            c_key.as_ptr(),
            out_buffer.as_mut_ptr() as *mut std::os::raw::c_char,
            out_buffer_size as c_int
        );
        if result <= 0 {
            println!("加密失败，返回值：{}", result);
            return;
        }

        // 根据返回的长度提取数据（可能是二进制数据，不一定是字符串）
        let encrypted_data = &out_buffer[..result as usize];

        // 如果是可打印字符串，可以尝试转换
        if let Ok(encrypted_str) = std::str::from_utf8(encrypted_data) {
            println!("返回值（字符串）：{}", encrypted_str);
        } else {
            // 如果是二进制数据，打印十六进制
            println!("返回值（二进制）：{:?}", encrypted_data);
        }


        const ADDR_CALL_DATA_ENCRYPT_END: u64 = 0x0045bd34;
        
        match alloc_and_patch(func_ptr as _, (ADDR_CALL_DATA_ENCRYPT_END - BASE) as _) {
            Ok(func) => {
                let hooked_func: DataEncryptC1 = mem::transmute(func);
                println!("获得hooked_func");
                let result = hooked_func(
                    c_in_data.as_ptr(),
                    c_key.as_ptr(),
                    out_buffer.as_mut_ptr() as *mut std::os::raw::c_char,
                    out_buffer_size as c_int
                );
                println!("hooked result {result:08X}");
                
            }
            Err(err) => panic!("{err}")
        }

        let calls = detect(func_ptr as _, BASE);
        println!("选择一个函数：");
        for (idx, &addr) in calls.iter().enumerate() {
            println!("{idx}. function call to {addr:08X}");
        }
        // 读取用户输入
        let mut input = String::new();
        stdin().read_line(&mut input).expect("无法读取输入");

        // 解析输入为数字
        match input.trim().parse::<usize>() {
            Ok(choice) if choice < calls.len() => {
                println!("你选择了: {}", choice);
                detect(calls[choice] + rva_offset, calls[choice]);
            }
            _ => {
                println!("无效输入，请输入0-7之间的数字");
            }
        }

    }
}
