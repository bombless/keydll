use libloading::{Library, Symbol};
use std::ffi::CString;
use std::os::raw::c_int;
use iced_x86::{Decoder, DecoderOptions, Formatter, Mnemonic, NasmFormatter};
use std::slice;

// 定义与 C 函数匹配的类型
type DataEncryptC1 = unsafe extern "stdcall" fn(
    *const std::os::raw::c_char,
    *const std::os::raw::c_char,
    *mut std::os::raw::c_char,
    c_int
) -> c_int;

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


        println!("First 16 bytes of the function:");
        for i in 0..16 {
            let byte = *func_ptr.add(i);
            print!("{:02X} ", byte);
        }
        println!();

        const BASE : u64 = 0x45bc84;
        let mut decoder = Decoder::with_ip(32, slice::from_raw_parts(func_ptr, 512), BASE, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();


        for instruction in decoder.iter() {
            // 反汇编当前指令
            let mut output = String::new();
            formatter.format(&instruction, &mut output);
            // let bytes = slice::from_raw_parts(func_ptr.offset(instruction.ip_rel_memory_address() as _), instruction.len());
            // println!("instruction.ip_rel_memory_address() {:08X}", instruction.ip_rel_memory_address());
            let bytes = slice::from_raw_parts(func_ptr.offset((instruction.ip() - BASE) as _), instruction.len());
            let bytes_string = format!("{bytes:X?}");
            println!("{:08X} {bytes_string:>32} {}", instruction.ip(), output);

            // 检查是否是无条件跳转（JMP）
            if instruction.mnemonic() == Mnemonic::Jmp {
                // println!("{instruction:?}");
                println!("==================\n You jump, I jump. \n==================");
                let add = instruction.ip_rel_memory_address();
                let offset = add - BASE;
                let mut decoder_jumped = Decoder::with_ip(32, slice::from_raw_parts(func_ptr.offset(offset as _), 256), add, DecoderOptions::NONE);
                for instruction in decoder_jumped.iter() {
                    let mut output = String::new();
                    formatter.format(&instruction, &mut output);
                    let bytes = slice::from_raw_parts(func_ptr.offset((instruction.ip() - BASE) as _), instruction.len());
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
        }


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
    }
}
