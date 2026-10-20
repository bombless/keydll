//! 交互式单步调试器（仅支持 32 位 x86 Windows）。
//!
//! 原理：
//! 1. 用一小段内联汇编把 EFLAGS 的 Trap Flag（TF，bit 8）置位，再 `call` 目标函数。
//!    CPU 会在目标函数执行第一条指令之前触发 `EXCEPTION_SINGLE_STEP`。
//! 2. 由 `AddVectoredExceptionHandler` 安装的处理函数接管该异常：反汇编当前指令、
//!    显示寄存器变化、读取用户命令，然后重新置位 TF 并返回
//!    `EXCEPTION_CONTINUE_EXECUTION`，于是下一条指令执行完又会回到处理函数，如此往复。
//! 3. 目标模块（Keydll.dll）之外的代码（kernel32、borlndmm.dll……）会被静默地单步通过：
//!    不打印、不分配内存。这样即便单步到一半被打断的是堆操作，处理函数也不会
//!    在堆处于中间状态时再去使用堆。
//!
//! 与旧的“截断函数再调用”方案相比，这里执行的始终是原始代码，因此相对 call/jmp、
//! 寄存器、栈上的数据都是真实的，不需要重定位，也能随时查看内存。
//!
//! 地址约定：显示和输入的代码地址默认使用 IDA 里的地址（模块被重定位时会自动换算），
//! 以便和 IDA 对照；寄存器和内存里的值则是真实地址。地址前加 `*` 表示强制使用真实地址。

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};
use std::ffi::c_void;
use std::fmt::Write as _;
use std::io::{self, BufRead, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

const TF: u32 = 0x100;
const RF: u32 = 0x1_0000;
const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

// ---------------------------------------------------------------------------
// 最小化的 Win32 FFI 声明。
// CONTEXT / EXCEPTION_RECORD 按 32 位 x86 的布局手写，这样不需要给 `windows` crate
// 额外开 feature，布局也由下面的单元测试固定住。
// ---------------------------------------------------------------------------
mod sys {
    use std::ffi::c_void;

    #[repr(C)]
    pub struct FloatingSaveArea {
        pub control_word: u32,
        pub status_word: u32,
        pub tag_word: u32,
        pub error_offset: u32,
        pub error_selector: u32,
        pub data_offset: u32,
        pub data_selector: u32,
        pub register_area: [u8; 80],
        pub cr0_npx_state: u32,
    }

    /// 32 位 x86 的 `CONTEXT`（共 0x2CC 字节）。
    #[repr(C)]
    pub struct Context {
        pub context_flags: u32,
        pub dr0: u32,
        pub dr1: u32,
        pub dr2: u32,
        pub dr3: u32,
        pub dr6: u32,
        pub dr7: u32,
        pub float_save: FloatingSaveArea,
        pub seg_gs: u32,
        pub seg_fs: u32,
        pub seg_es: u32,
        pub seg_ds: u32,
        pub edi: u32,
        pub esi: u32,
        pub ebx: u32,
        pub edx: u32,
        pub ecx: u32,
        pub eax: u32,
        pub ebp: u32,
        pub eip: u32,
        pub seg_cs: u32,
        pub eflags: u32,
        pub esp: u32,
        pub seg_ss: u32,
        pub extended_registers: [u8; 512],
    }

    #[repr(C)]
    pub struct ExceptionRecord {
        pub exception_code: u32,
        pub exception_flags: u32,
        pub exception_record: *mut ExceptionRecord,
        pub exception_address: *mut c_void,
        pub number_parameters: u32,
        pub exception_information: [usize; 15],
    }

    #[repr(C)]
    pub struct ExceptionPointers {
        pub exception_record: *mut ExceptionRecord,
        pub context_record: *mut Context,
    }

    pub type VectoredHandler = unsafe extern "system" fn(*mut ExceptionPointers) -> i32;

    #[cfg_attr(windows, link(name = "kernel32"))]
    unsafe extern "system" {
        pub fn AddVectoredExceptionHandler(first: u32, handler: Option<VectoredHandler>) -> *mut c_void;
        pub fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
        pub fn GetCurrentThreadId() -> u32;
        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn ReadProcessMemory(
            process: *mut c_void,
            base: *const c_void,
            buffer: *mut c_void,
            size: usize,
            bytes_read: *mut usize,
        ) -> i32;
        pub fn GetModuleHandleExW(flags: u32, module_name: *const c_void, module: *mut *mut c_void) -> i32;
    }
}

use sys::{Context, ExceptionPointers};

// ---------------------------------------------------------------------------
// 安全读内存：直接解引用坏指针会在处理函数里再触发访问违规，所以一律走 ReadProcessMemory。
// ---------------------------------------------------------------------------

/// 尽可能多地读取 `buf.len()` 字节，返回实际读到的字节数。
/// 按 16 字节边界分块，保证每块都不会跨页，这样遇到不可读页时前面的部分仍然可用。
fn read_mem(addr: u32, buf: &mut [u8]) -> usize {
    let mut done = 0usize;
    while done < buf.len() {
        let cur = addr.wrapping_add(done as u32);
        let chunk = (buf.len() - done).min(16 - (cur as usize & 15));
        let mut got = 0usize;
        let ok = unsafe {
            sys::ReadProcessMemory(
                sys::GetCurrentProcess(),
                cur as usize as *const c_void,
                buf[done..].as_mut_ptr().cast(),
                chunk,
                &mut got,
            )
        };
        if ok == 0 || got != chunk {
            break;
        }
        done += chunk;
    }
    done
}

fn read_u32(addr: u32) -> Option<u32> {
    let mut b = [0u8; 4];
    (read_mem(addr, &mut b) == 4).then(|| u32::from_le_bytes(b))
}

fn read_u16(addr: u32) -> Option<u16> {
    let mut b = [0u8; 2];
    (read_mem(addr, &mut b) == 2).then(|| u16::from_le_bytes(b))
}

// ---------------------------------------------------------------------------
// 寄存器快照与格式化
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
struct Regs {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
    esp: u32,
    /// 已去掉 TF / RF，它们是单步机制自己改的，对用户没有意义。
    eflags: u32,
}

impl Regs {
    const ZERO: Regs = Regs { eax: 0, ebx: 0, ecx: 0, edx: 0, esi: 0, edi: 0, ebp: 0, esp: 0, eflags: 0 };

    fn from_ctx(c: &Context) -> Regs {
        Regs {
            eax: c.eax,
            ebx: c.ebx,
            ecx: c.ecx,
            edx: c.edx,
            esi: c.esi,
            edi: c.edi,
            ebp: c.ebp,
            esp: c.esp,
            eflags: c.eflags & !(TF | RF),
        }
    }
}

fn flags_str(f: u32) -> String {
    const NAMES: [(u32, &str); 7] =
        [(0x1, "CF"), (0x4, "PF"), (0x10, "AF"), (0x40, "ZF"), (0x80, "SF"), (0x400, "DF"), (0x800, "OF")];
    let set: Vec<&str> = NAMES.iter().filter(|(bit, _)| f & bit != 0).map(|&(_, n)| n).collect();
    if set.is_empty() { "-".to_string() } else { set.join(" ") }
}

/// 列出 `old` 到 `new` 之间发生变化的寄存器；没有变化则返回空串。
fn diff_regs(old: &Regs, new: &Regs) -> String {
    let items = [
        ("eax", old.eax, new.eax),
        ("ebx", old.ebx, new.ebx),
        ("ecx", old.ecx, new.ecx),
        ("edx", old.edx, new.edx),
        ("esi", old.esi, new.esi),
        ("edi", old.edi, new.edi),
        ("ebp", old.ebp, new.ebp),
        ("esp", old.esp, new.esp),
    ];
    let mut out = String::new();
    for (name, a, b) in items {
        if a != b {
            if !out.is_empty() {
                out.push_str("  ");
            }
            let _ = write!(out, "{name}: {a:08X} -> {b:08X}");
        }
    }
    if old.eflags != new.eflags {
        if !out.is_empty() {
            out.push_str("  ");
        }
        let _ = write!(out, "flags: [{}] -> [{}]", flags_str(old.eflags), flags_str(new.eflags));
    }
    out
}

fn hexdump(base: u32, data: &[u8]) -> String {
    let mut out = String::new();
    for (i, row) in data.chunks(16).enumerate() {
        let _ = write!(out, "{:08X}  ", base.wrapping_add((i * 16) as u32));
        for j in 0..16 {
            match row.get(j) {
                Some(b) => {
                    let _ = write!(out, "{b:02X} ");
                }
                None => out.push_str("   "),
            }
            if j == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        out.extend(row.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }));
        out.push_str("|\n");
    }
    out
}

fn parse_hex(s: &str) -> Option<u32> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    // 兼容 IDA 风格的 45B9E0h
    let s = s.strip_suffix('h').or_else(|| s.strip_suffix('H')).unwrap_or(s);
    u32::from_str_radix(s, 16).ok()
}

fn reg_get(c: &Context, name: &str) -> Option<u32> {
    Some(match name {
        "eax" => c.eax,
        "ebx" => c.ebx,
        "ecx" => c.ecx,
        "edx" => c.edx,
        "esi" => c.esi,
        "edi" => c.edi,
        "ebp" => c.ebp,
        "esp" => c.esp,
        "eip" => c.eip,
        "eflags" => c.eflags & !(TF | RF),
        _ => return None,
    })
}

fn reg_set(c: &mut Context, name: &str, value: u32) -> bool {
    let slot = match name {
        "eax" => &mut c.eax,
        "ebx" => &mut c.ebx,
        "ecx" => &mut c.ecx,
        "edx" => &mut c.edx,
        "esi" => &mut c.esi,
        "edi" => &mut c.edi,
        "ebp" => &mut c.ebp,
        "esp" => &mut c.esp,
        "eip" => &mut c.eip,
        "eflags" => {
            // 不让用户把 TF 改掉，否则单步就断了
            c.eflags = (value & !RF) | TF;
            return true;
        }
        _ => return false,
    };
    *slot = value;
    true
}

// ---------------------------------------------------------------------------
// 调试器状态
// ---------------------------------------------------------------------------

/// 从当前停止点恢复执行后的行为。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Resume {
    /// 再执行 n 条（模块内的）指令：每条都打印，执行完第 n 条后停下来等命令。
    Steps(u32),
    /// 步过 call：静默执行，直到回到 `ret` 且 esp 不低于 `esp`。
    Over { ret: u32, esp: u32 },
    /// 静默执行，直到命中断点。
    Break,
    /// 清除 TF，全速跑完。
    Free,
}

struct StepState {
    module_lo: u32,
    module_hi: u32,
    /// 真实地址 - IDA 地址
    delta: u32,
    /// 模块在 IDA 里的地址范围，用来判断用户输入的是 IDA 地址还是真实地址
    ida_lo: u32,
    ida_hi: u32,
    started: bool,
    finished: bool,
    entry_esp: u32,
    ret_addr: u32,
    steps: u64,
    resume: Resume,
    /// 断点（真实地址）
    breakpoints: Vec<u32>,
    prev: Regs,
}

impl StepState {
    const fn new() -> StepState {
        StepState {
            module_lo: 0,
            module_hi: 0,
            delta: 0,
            ida_lo: 0,
            ida_hi: 0,
            started: false,
            finished: false,
            entry_esp: 0,
            ret_addr: 0,
            steps: 0,
            resume: Resume::Steps(1),
            breakpoints: Vec::new(),
            prev: Regs::ZERO,
        }
    }

    fn in_module(&self, addr: u32) -> bool {
        (self.module_lo..self.module_hi).contains(&addr)
    }

    fn to_ida(&self, real: u32) -> u32 {
        real.wrapping_sub(self.delta)
    }

    /// 用户输入的地址 -> 真实地址：落在模块 IDA 范围内的按 IDA 地址换算，否则原样使用。
    fn to_real(&self, addr: u32) -> u32 {
        if (self.ida_lo..self.ida_hi).contains(&addr) { addr.wrapping_add(self.delta) } else { addr }
    }

    /// 解析 `[*]hex | reg` 再加上可选的 `+hex` / `-hex`。
    fn eval(&self, ctx: &Context, expr: &str) -> Option<u32> {
        let expr = expr.trim().to_ascii_lowercase();
        let split = expr.find(['+', '-']);
        let (term, tail) = match split {
            Some(i) => (&expr[..i], Some((&expr[i + 1..], expr.as_bytes()[i] == b'-'))),
            None => (&expr[..], None),
        };
        let term = term.trim();
        let base = if let Some(v) = reg_get(ctx, term) {
            v
        } else if let Some(raw) = term.strip_prefix('*') {
            parse_hex(raw)?
        } else {
            self.to_real(parse_hex(term)?)
        };
        Some(match tail {
            None => base,
            Some((off, neg)) => {
                let off = parse_hex(off)?;
                if neg { base.wrapping_sub(off) } else { base.wrapping_add(off) }
            }
        })
    }

    /// 解码 `real` 处的一条指令，指令地址按 IDA 地址计算，这样分支目标能直接对上 IDA。
    fn decode(&self, real: u32) -> Option<(Instruction, [u8; 15])> {
        let mut bytes = [0u8; 15];
        let n = read_mem(real, &mut bytes);
        if n == 0 {
            return None;
        }
        let mut decoder = Decoder::with_ip(32, &bytes[..n], self.to_ida(real) as u64, DecoderOptions::NONE);
        let ins = decoder.decode();
        (!ins.is_invalid()).then_some((ins, bytes))
    }

    fn format_ins(&self, real: u32, ins: &Instruction, bytes: &[u8; 15]) -> String {
        let mut formatter = NasmFormatter::new();
        let mut text = String::new();
        formatter.format(ins, &mut text);
        let mut hex = String::new();
        for (i, b) in bytes[..ins.len()].iter().enumerate() {
            if i > 0 {
                hex.push(' ');
            }
            let _ = write!(hex, "{b:02X}");
        }
        format!("{:08X}  {hex:<24} {text}", self.to_ida(real))
    }

    /// 打印“自上次显示以来的寄存器变化”和即将执行的指令。
    fn show_stop(&mut self, ctx: &Context) {
        let now = Regs::from_ctx(ctx);
        let changes = diff_regs(&self.prev, &now);
        if !changes.is_empty() {
            println!("    ; {changes}");
        }
        self.prev = now;
        match self.decode(ctx.eip) {
            Some((ins, bytes)) => println!("{}", self.format_ins(ctx.eip, &ins, &bytes)),
            None => println!("{:08X}  <无法反汇编/读取>", self.to_ida(ctx.eip)),
        }
    }

    fn print_regs(&self, ctx: &Context) {
        let r = Regs::from_ctx(ctx);
        println!("EAX={:08X} EBX={:08X} ECX={:08X} EDX={:08X}", r.eax, r.ebx, r.ecx, r.edx);
        println!("ESI={:08X} EDI={:08X} EBP={:08X} ESP={:08X}", r.esi, r.edi, r.ebp, r.esp);
        println!(
            "EIP={:08X} (IDA {:08X})  EFLAGS={:08X} [{}]",
            ctx.eip,
            self.to_ida(ctx.eip),
            r.eflags,
            flags_str(r.eflags)
        );
    }
}

static STATE: Mutex<StepState> = Mutex::new(StepState::new());
/// 正在被单步的线程 id，0 表示当前没有在单步。
/// 单独放在原子变量里，是为了让其它线程触发的异常不必去争用 STATE 的锁。
static TRACED_THREAD: AtomicU32 = AtomicU32::new(0);

const HELP: &str = "\
命令（括号里是缩写）：
  step [N]   (s, 直接回车)  单步进入；带 N 则连续执行 N 条并逐条打印
  next       (n)            单步，但把 call 当作一条指令步过
  continue   (c)            运行到下一个断点；没有断点时等同于 go
  go         (g, q)         取消单步，让函数全速跑完
  regs       (r)            显示全部寄存器
  set REG VAL               修改寄存器，例如 set eax 1234（含 eip，用来跳转）
  mem ADDR [LEN]  (m, x)    十六进制查看内存，ADDR 可以是寄存器，如 m esp+8 40
  u [ADDR] [N]              反汇编 N 条（默认从当前 EIP 开始 10 条，不执行）
  b ADDR                    设置断点（IDA 地址）；bl 列表；bd ADDR 删除；bc 全部清除
  help       (h, ?)         显示本帮助
说明：代码地址默认是 IDA 地址（自动换算重定位），地址前加 * 表示真实地址；
      模块之外的代码（kernel32 等）会被自动步过。";

/// 处理一次单步陷阱。返回 `true` 表示继续单步（重新置位 TF）。
fn on_step(st: &mut StepState, ctx: &mut Context) -> bool {
    let eip = ctx.eip;

    if !st.started {
        // 第一次陷阱：目标函数还没执行任何指令，[esp] 就是返回地址。
        st.started = true;
        st.entry_esp = ctx.esp;
        st.ret_addr = read_u32(ctx.esp).unwrap_or(0);
        st.prev = Regs::from_ctx(ctx);
        st.resume = Resume::Steps(1);
        println!(
            "== 已停在函数入口 {:08X}（IDA {:08X}），返回地址 {:08X} ==",
            eip,
            st.to_ida(eip),
            st.ret_addr
        );
        println!("输入 help 查看命令。");
    } else {
        st.steps += 1;
        if eip == st.ret_addr && ctx.esp > st.entry_esp {
            println!("== 函数已返回，EAX={:08X}，共单步 {} 条指令 ==", ctx.eax, st.steps);
            st.finished = true;
            return false;
        }
    }

    let in_module = st.in_module(eip);
    let hit_bp = in_module && st.breakpoints.contains(&eip);
    let mut stop = hit_bp;
    let mut trace_only = false;

    match st.resume {
        Resume::Free => return false,
        Resume::Steps(n) => {
            if in_module {
                if n > 1 {
                    st.resume = Resume::Steps(n - 1);
                    trace_only = true;
                } else {
                    stop = true;
                }
            }
        }
        Resume::Over { ret, esp } => {
            if eip == ret && ctx.esp >= esp {
                stop = true;
            }
        }
        Resume::Break => {}
    }

    if hit_bp {
        println!("== 命中断点 {:08X} ==", st.to_ida(eip));
    }
    if trace_only {
        st.show_stop(ctx);
        return true;
    }
    if !stop {
        return true;
    }

    st.show_stop(ctx);
    prompt(st, ctx)
}

/// 命令循环。返回 `true` 表示继续单步，`false` 表示不再单步。
fn prompt(st: &mut StepState, ctx: &mut Context) -> bool {
    let stdin = io::stdin();
    loop {
        print!("(dbg) ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            // EOF（例如输入被重定向且已读完）：别死循环，直接让函数跑完
            Ok(0) | Err(_) => {
                println!();
                st.resume = Resume::Free;
                return false;
            }
            Ok(_) => {}
        }
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("s").to_ascii_lowercase();
        let rest: Vec<&str> = parts.collect();

        match cmd.as_str() {
            "s" | "step" => {
                let n = rest.first().and_then(|v| v.parse::<u32>().ok()).unwrap_or(1).max(1);
                st.resume = Resume::Steps(n);
                return true;
            }
            "n" | "next" => {
                st.resume = match st.decode(ctx.eip) {
                    Some((ins, _)) if matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall) => {
                        Resume::Over { ret: ctx.eip.wrapping_add(ins.len() as u32), esp: ctx.esp }
                    }
                    _ => Resume::Steps(1),
                };
                return true;
            }
            "c" | "continue" => {
                if st.breakpoints.is_empty() {
                    st.resume = Resume::Free;
                    return false;
                }
                st.resume = Resume::Break;
                return true;
            }
            "g" | "go" | "q" | "quit" => {
                st.resume = Resume::Free;
                return false;
            }
            "r" | "regs" => st.print_regs(ctx),
            "set" => match (rest.first(), rest.get(1).and_then(|v| st.eval(ctx, v))) {
                (Some(reg), Some(value)) => {
                    if reg_set(ctx, &reg.to_ascii_lowercase(), value) {
                        println!("{} = {:08X}", reg.to_ascii_lowercase(), value);
                    } else {
                        println!("未知寄存器：{reg}");
                    }
                }
                _ => println!("用法：set REG VALUE"),
            },
            "m" | "x" | "mem" => {
                let Some(addr) = rest.first().and_then(|e| st.eval(ctx, e)) else {
                    println!("用法：mem ADDR [LEN]");
                    continue;
                };
                let len = rest.get(1).and_then(|v| parse_hex(v)).unwrap_or(0x40).clamp(1, 0x1000) as usize;
                let mut buf = vec![0u8; len];
                let got = read_mem(addr, &mut buf);
                if got == 0 {
                    println!("无法读取 {addr:08X}");
                } else {
                    print!("{}", hexdump(addr, &buf[..got]));
                    if got < len {
                        println!("（只读到 {got} 字节，{:08X} 起不可读）", addr.wrapping_add(got as u32));
                    }
                }
            }
            "u" => {
                let mut addr = match rest.first() {
                    Some(e) => match st.eval(ctx, e) {
                        Some(a) => a,
                        None => {
                            println!("地址无效：{e}");
                            continue;
                        }
                    },
                    None => ctx.eip,
                };
                let count = rest.get(1).and_then(|v| v.parse::<usize>().ok()).unwrap_or(10).clamp(1, 200);
                for _ in 0..count {
                    match st.decode(addr) {
                        Some((ins, bytes)) => {
                            let marker = if addr == ctx.eip { "=>" } else { "  " };
                            println!("{marker} {}", st.format_ins(addr, &ins, &bytes));
                            addr = addr.wrapping_add(ins.len() as u32);
                        }
                        None => {
                            println!("   {:08X}  <无法反汇编/读取>", st.to_ida(addr));
                            break;
                        }
                    }
                }
            }
            "b" | "bp" => match rest.first().and_then(|e| st.eval(ctx, e)) {
                Some(addr) if st.in_module(addr) => {
                    if !st.breakpoints.contains(&addr) {
                        st.breakpoints.push(addr);
                    }
                    println!("断点：{:08X}（真实地址 {:08X}）", st.to_ida(addr), addr);
                }
                Some(_) => println!("该地址不在 Keydll.dll 内，断点只在模块内生效"),
                None => println!("用法：b ADDR"),
            },
            "bl" => {
                if st.breakpoints.is_empty() {
                    println!("没有断点");
                }
                for (i, &a) in st.breakpoints.iter().enumerate() {
                    println!("{i}: {:08X}（真实地址 {a:08X}）", st.to_ida(a));
                }
            }
            "bd" => match rest.first().and_then(|e| st.eval(ctx, e)) {
                Some(addr) => {
                    let before = st.breakpoints.len();
                    st.breakpoints.retain(|&a| a != addr);
                    if st.breakpoints.len() == before {
                        println!("该地址没有断点");
                    }
                }
                None => println!("用法：bd ADDR"),
            },
            "bc" => {
                st.breakpoints.clear();
                println!("已清除全部断点");
            }
            "h" | "help" | "?" => println!("{HELP}"),
            other => println!("未知命令：{other}（输入 help 查看帮助）"),
        }
    }
}

unsafe extern "system" fn veh(info: *mut ExceptionPointers) -> i32 {
    // SAFETY: 系统保证 info 及其内部指针在回调期间有效。
    let (record, ctx) = unsafe { (&*(*info).exception_record, &mut *(*info).context_record) };
    if record.exception_code != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if TRACED_THREAD.load(Ordering::Relaxed) != unsafe { sys::GetCurrentThreadId() } {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if guard.finished {
        ctx.eflags &= !TF;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if on_step(&mut guard, ctx) {
        ctx.eflags |= TF;
    } else {
        ctx.eflags &= !TF;
    }
    EXCEPTION_CONTINUE_EXECUTION
}

// ---------------------------------------------------------------------------
// 入口：置位 TF 后调用目标函数
// ---------------------------------------------------------------------------

/// 以 stdcall 方式调用 `entry(args[0], args[1], args[2], args[3])`，并在调用前置位 TF。
///
/// `popfd` 之后 CPU 会让紧接着的那条指令（也就是 `call`）正常执行完才触发单步陷阱，
/// 所以第一次陷阱时 EIP 正好是目标函数的第一条指令。
/// 目标函数返回后 `pushfd/and/popfd` 再把 TF 清掉（正常情况下处理函数在检测到返回时就已经清了，
/// 这里是兜底）。
#[cfg(target_arch = "x86")]
#[inline(never)]
unsafe fn call_with_trap_flag(entry: usize, args: &[usize; 4]) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "push dword ptr [{a} + 12]",
            "push dword ptr [{a} + 8]",
            "push dword ptr [{a} + 4]",
            "push dword ptr [{a}]",
            "pushfd",
            "or dword ptr [esp], 0x100",
            "popfd",
            "call {f}",
            "pushfd",
            "and dword ptr [esp], 0xFFFFFEFF",
            "popfd",
            a = in(reg) args.as_ptr(),
            f = in(reg) entry,
            out("eax") ret,
            clobber_abi("C"),
        );
    }
    ret
}

#[cfg(not(target_arch = "x86"))]
unsafe fn call_with_trap_flag(_entry: usize, _args: &[usize; 4]) -> i32 {
    unreachable!("单步调试只支持 32 位 x86 目标（i686-pc-windows-*）")
}

struct ModuleInfo {
    base: u32,
    size: u32,
    image_base: u32,
}

/// 找到包含 `addr` 的模块，并从 PE 头里读出 ImageBase 和 SizeOfImage。
fn module_of(addr: u32) -> Result<ModuleInfo, String> {
    let mut handle: *mut c_void = std::ptr::null_mut();
    // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS (0x4) | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT (0x2)
    let ok = unsafe { sys::GetModuleHandleExW(0x4 | 0x2, addr as usize as *const c_void, &mut handle) };
    if ok == 0 || handle.is_null() {
        return Err(format!("找不到包含 {addr:08X} 的模块"));
    }
    let base = handle as usize as u32;
    let bad = || format!("读取 {base:08X} 处的 PE 头失败");
    let nt = base.wrapping_add(read_u32(base.wrapping_add(0x3C)).ok_or_else(bad)?);
    if read_u32(nt).ok_or_else(bad)? != 0x0000_4550 {
        return Err("PE 签名不对".to_string());
    }
    let opt = nt.wrapping_add(24);
    if read_u16(opt).ok_or_else(bad)? != 0x10B {
        return Err("不是 32 位（PE32）模块".to_string());
    }
    Ok(ModuleInfo {
        base,
        size: read_u32(opt.wrapping_add(56)).ok_or_else(bad)?,
        image_base: read_u32(opt.wrapping_add(28)).ok_or_else(bad)?,
    })
}

/// 在交互式单步调试器里运行 `entry`（stdcall、4 个参数），返回目标函数的返回值。
///
/// `ida_entry` 是该函数在 IDA 中的地址，只用来校验重定位换算是否正确。
///
/// # Safety
/// `entry` 必须指向一个 stdcall、恰好接收 4 个机器字参数的 32 位函数，
/// `args` 里的指针在调用期间必须有效。
pub unsafe fn run(entry: *const u8, ida_entry: u32, args: [usize; 4]) -> Result<i32, String> {
    if !cfg!(target_arch = "x86") {
        return Err("单步调试只支持 32 位 x86 目标（i686-pc-windows-*）".to_string());
    }
    let entry_addr = entry as usize as u32;
    let module = module_of(entry_addr)?;
    let delta = module.base.wrapping_sub(module.image_base);

    println!(
        "模块基址 {:08X}，大小 {:X}h，首选基址 {:08X}，重定位偏移 {:08X}",
        module.base, module.size, module.image_base, delta
    );
    let mapped = entry_addr.wrapping_sub(delta);
    if mapped != ida_entry {
        println!("警告：入口换算成 IDA 地址是 {mapped:08X}，和预期的 {ida_entry:08X} 不一致，IDA 地址可能对不上");
    }

    {
        let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
        *st = StepState::new();
        st.module_lo = module.base;
        st.module_hi = module.base.wrapping_add(module.size);
        st.delta = delta;
        st.ida_lo = module.image_base;
        st.ida_hi = module.image_base.wrapping_add(module.size);
    }

    let handler = unsafe { sys::AddVectoredExceptionHandler(1, Some(veh)) };
    if handler.is_null() {
        return Err("AddVectoredExceptionHandler 失败".to_string());
    }
    TRACED_THREAD.store(unsafe { sys::GetCurrentThreadId() }, Ordering::SeqCst);

    let result = unsafe { call_with_trap_flag(entry_addr as usize, &args) };

    TRACED_THREAD.store(0, Ordering::SeqCst);
    unsafe { sys::RemoveVectoredExceptionHandler(handler) };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn context_layout_matches_win32_x86() {
        assert_eq!(size_of::<sys::FloatingSaveArea>(), 112);
        assert_eq!(offset_of!(Context, float_save), 0x1C);
        assert_eq!(offset_of!(Context, seg_gs), 0x8C);
        assert_eq!(offset_of!(Context, edi), 0x9C);
        assert_eq!(offset_of!(Context, eax), 0xB0);
        assert_eq!(offset_of!(Context, ebp), 0xB4);
        assert_eq!(offset_of!(Context, eip), 0xB8);
        assert_eq!(offset_of!(Context, eflags), 0xC0);
        assert_eq!(offset_of!(Context, esp), 0xC4);
        assert_eq!(offset_of!(Context, extended_registers), 0xCC);
        assert_eq!(size_of::<Context>(), 0x2CC);
    }

    #[test]
    fn exception_record_code_is_first_field() {
        assert_eq!(offset_of!(sys::ExceptionRecord, exception_code), 0);
        assert_eq!(offset_of!(sys::ExceptionPointers, exception_record), 0);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn exception_record_layout_x86() {
        assert_eq!(offset_of!(sys::ExceptionRecord, exception_address), 12);
        assert_eq!(size_of::<sys::ExceptionRecord>(), 80);
        assert_eq!(offset_of!(sys::ExceptionPointers, context_record), 4);
    }

    #[test]
    fn parse_hex_variants() {
        assert_eq!(parse_hex("45b9e0"), Some(0x45B9E0));
        assert_eq!(parse_hex("0x45B9E0"), Some(0x45B9E0));
        assert_eq!(parse_hex("45B9E0h"), Some(0x45B9E0));
        assert_eq!(parse_hex(" ff "), Some(0xFF));
        assert_eq!(parse_hex("xyz"), None);
        assert_eq!(parse_hex(""), None);
        assert_eq!(parse_hex("123456789"), None);
    }

    fn zero_ctx() -> Box<Context> {
        // Context 里没有任何需要非零初始化的字段
        unsafe { Box::new(std::mem::zeroed()) }
    }

    fn state() -> StepState {
        let mut st = StepState::new();
        st.module_lo = 0x7000_0000;
        st.module_hi = 0x7007_0000;
        st.delta = 0x7000_0000 - 0x40_0000;
        st.ida_lo = 0x40_0000;
        st.ida_hi = 0x47_0000;
        st
    }

    #[test]
    fn address_mapping() {
        let st = state();
        assert_eq!(st.to_ida(0x7005_BC84), 0x45BC84);
        assert_eq!(st.to_real(0x45BC84), 0x7005_BC84);
        // 不在 IDA 范围内的地址原样使用
        assert_eq!(st.to_real(0x0019_FF00), 0x0019_FF00);
        assert!(st.in_module(0x7005_BC84));
        assert!(!st.in_module(0x7007_0000));
    }

    #[test]
    fn expression_evaluation() {
        let st = state();
        let mut ctx = zero_ctx();
        ctx.esp = 0x0019_FF00;
        ctx.eax = 0x1000;
        assert_eq!(st.eval(&ctx, "esp"), Some(0x0019_FF00));
        assert_eq!(st.eval(&ctx, "ESP+8"), Some(0x0019_FF08));
        assert_eq!(st.eval(&ctx, "esp - 10"), Some(0x0019_FEF0));
        assert_eq!(st.eval(&ctx, "45bc84"), Some(0x7005_BC84));
        assert_eq!(st.eval(&ctx, "*45bc84"), Some(0x45BC84));
        assert_eq!(st.eval(&ctx, "eax+4"), Some(0x1004));
        assert_eq!(st.eval(&ctx, "nope"), None);
        assert_eq!(st.eval(&ctx, "esp+zz"), None);
    }

    #[test]
    fn register_set_keeps_trap_flag() {
        let mut ctx = zero_ctx();
        assert!(reg_set(&mut ctx, "eax", 0x1234));
        assert_eq!(ctx.eax, 0x1234);
        assert!(reg_set(&mut ctx, "eflags", 0x246));
        assert_eq!(ctx.eflags & TF, TF);
        assert_eq!(reg_get(&ctx, "eflags"), Some(0x246));
        assert!(!reg_set(&mut ctx, "foo", 1));
    }

    #[test]
    fn reg_diff_and_flags() {
        let a = Regs { eax: 1, eflags: 0x40, ..Regs::ZERO };
        let b = Regs { eax: 2, esp: 0x10, eflags: 0x41, ..Regs::ZERO };
        let d = diff_regs(&a, &b);
        assert_eq!(d, "eax: 00000001 -> 00000002  esp: 00000000 -> 00000010  flags: [ZF] -> [CF ZF]");
        assert_eq!(diff_regs(&a, &a), "");
        assert_eq!(flags_str(0), "-");
    }

    #[test]
    fn hexdump_format() {
        let data: Vec<u8> = (0x41..0x41 + 20).collect();
        let s = hexdump(0x1000, &data);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("00001000  41 42 43 44 45 46 47 48  49 4A 4B 4C 4D 4E 4F 50  |ABCDEFGHIJKLMNOP|"));
        assert!(lines[1].starts_with("00001010  51 52 53 54"));
        assert!(lines[1].ends_with("|QRST|"));
    }

    #[test]
    fn step_over_only_for_calls() {
        // call 的判断依赖 iced 的 flow_control，这里固定住预期
        let mut d = Decoder::with_ip(32, &[0xE8, 0x00, 0x00, 0x00, 0x00], 0x1000, DecoderOptions::NONE);
        assert_eq!(d.decode().flow_control(), FlowControl::Call);
        let mut d = Decoder::with_ip(32, &[0xFF, 0x15, 0x00, 0x10, 0x40, 0x00], 0x1000, DecoderOptions::NONE);
        assert_eq!(d.decode().flow_control(), FlowControl::IndirectCall);
        let mut d = Decoder::with_ip(32, &[0x55], 0x1000, DecoderOptions::NONE);
        assert_eq!(d.decode().flow_control(), FlowControl::Next);
    }
}
