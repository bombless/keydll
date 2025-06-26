use libloading::{Library, Symbol};
use std::ffi::CString;
use std::os::raw::c_int;

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
