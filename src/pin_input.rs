use std::io::{self, Write};
use zeroize::Zeroize;

struct TermiosGuard {
    original: libc::termios,
    fd: i32,
}

impl TermiosGuard {
    fn new() -> Option<Self> {
        let fd = libc::STDIN_FILENO;
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }
        let mut raw = original;
        raw.c_lflag &= !(libc::ECHO | libc::ICANON);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { original, fd })
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

pub fn get_pin() -> usize {
    const MAX_UINT64_STR: &str = "18446744073709551615";
    const MAX_PIN_LENGTH: usize = 20;

    print!("\nPIN: ");
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    let _guard = if is_tty { TermiosGuard::new() } else { None };

    let mut buf = [0u8; 1];
    loop {
        let bytes_read =
            unsafe { libc::read(libc::STDIN_FILENO, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if bytes_read == 0 {
            break;
        }
        if bytes_read < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        let ch = buf[0];
        if ch == b'\n' || ch == b'\r' {
            break;
        }
        if input.len() >= MAX_PIN_LENGTH {
            continue;
        }
        if ch >= b'0' && ch <= b'9' {
            input.push(ch as char);
            if is_tty {
                print!("*");
                io::stdout().flush().unwrap_or(());
            }
        } else if (ch == 8 || ch == 127) && !input.is_empty() {
            if is_tty {
                print!("\x08 \x08");
                io::stdout().flush().unwrap_or(());
            }
            input.pop();
        }
    }

    println!();
    io::stdout().flush().unwrap_or(());

    if input.is_empty() || (input.len() == MAX_PIN_LENGTH && input.as_str() > MAX_UINT64_STR) {
        if !input.is_empty() {
            input.zeroize();
            input.clear();
        }
        return 0;
    }

    let result = input.parse::<usize>().unwrap_or(0);
    if !input.is_empty() {
        input.zeroize();
        input.clear();
    }
    result
}
