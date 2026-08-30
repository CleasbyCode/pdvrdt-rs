use anyhow::{anyhow, bail, Result};
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};

const MAX_PIN_LENGTH: usize = 20;
const MAX_UINT64_STR: &[u8; MAX_PIN_LENGTH] = b"18446744073709551615";

struct TermiosGuard {
    original: libc::termios,
    old_signal_mask: libc::sigset_t,
    signal_fd: libc::c_int,
    terminal_active: bool,
    signals_blocked: bool,
}

enum ReadEvent {
    Byte(u8),
    Eof,
    Interrupted,
    Signal(libc::c_int),
    Error,
}

impl TermiosGuard {
    fn inactive() -> Self {
        Self {
            // SAFETY: `termios` and `sigset_t` are plain C data structures for
            // which an all-zero value is valid storage. They are not used until
            // the corresponding libc call has initialized them.
            original: unsafe { std::mem::zeroed() },
            old_signal_mask: unsafe { std::mem::zeroed() },
            signal_fd: -1,
            terminal_active: false,
            signals_blocked: false,
        }
    }

    fn set_terminal_attributes(attributes: &libc::termios) -> io::Result<()> {
        loop {
            // SAFETY: `attributes` points to a live `termios` value and stdin is
            // the descriptor whose settings were read during construction.
            if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, attributes) } == 0 {
                return Ok(());
            }

            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn new(is_tty: bool) -> Result<Self> {
        let mut guard = Self::inactive();
        if !is_tty {
            return Ok(guard);
        }

        // SAFETY: `sigset_t` is a plain C data structure initialized by
        // `sigemptyset` before it is passed to any other signal API.
        let mut guarded_signals: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: All pointers refer to live `sigset_t` values and all signal
        // constants are valid on the Linux-only target supported by this crate.
        let signal_set_ok = unsafe {
            libc::sigemptyset(&mut guarded_signals) == 0
                && libc::sigaddset(&mut guarded_signals, libc::SIGINT) == 0
                && libc::sigaddset(&mut guarded_signals, libc::SIGTERM) == 0
                && libc::sigaddset(&mut guarded_signals, libc::SIGHUP) == 0
                && libc::sigaddset(&mut guarded_signals, libc::SIGQUIT) == 0
                && libc::sigaddset(&mut guarded_signals, libc::SIGTSTP) == 0
        };
        if !signal_set_ok {
            bail!("Terminal Error: Unable to prepare signal protection for PIN entry.");
        }

        // SAFETY: Both signal-set pointers refer to initialized, live storage.
        if unsafe {
            libc::sigprocmask(
                libc::SIG_BLOCK,
                &guarded_signals,
                &mut guard.old_signal_mask,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            bail!(
                "Terminal Error: Unable to protect PIN entry from signals: {}",
                error
            );
        }
        guard.signals_blocked = true;

        // SAFETY: `guarded_signals` remains live for this call. signalfd copies
        // the mask into the kernel object, so it need not outlive the call.
        guard.signal_fd =
            unsafe { libc::signalfd(-1, &guarded_signals, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if guard.signal_fd < 0 {
            let error = io::Error::last_os_error();
            return Err(anyhow!(
                "Terminal Error: Unable to monitor signals during PIN entry: {}",
                error
            ));
        }

        // SAFETY: `original` is writable storage for a `termios` value and stdin
        // was established as a TTY by the caller.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut guard.original) } != 0 {
            let error = io::Error::last_os_error();
            return Err(anyhow!(
                "Terminal Error: Unable to read terminal settings for secure PIN entry: {}",
                error
            ));
        }

        let mut raw = guard.original;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        if let Err(error) = Self::set_terminal_attributes(&raw) {
            return Err(anyhow!(
                "Terminal Error: Unable to disable terminal echo for secure PIN entry: {}",
                error
            ));
        }
        guard.terminal_active = true;

        Ok(guard)
    }

    fn masks_input(&self) -> bool {
        self.terminal_active
    }

    fn close_signal_fd(&mut self) {
        if self.signal_fd < 0 {
            return;
        }

        // Linux releases a descriptor even when close reports EINTR. Mark it
        // closed first and never retry, avoiding a recycled-descriptor race.
        let signal_fd = std::mem::replace(&mut self.signal_fd, -1);
        // SAFETY: `signal_fd` is owned by this guard and has not been closed yet.
        unsafe {
            libc::close(signal_fd);
        }
    }

    fn restore_no_throw(&mut self) {
        // Restore the terminal before unblocking signals. A pending terminating
        // signal must never be allowed to strand the terminal in no-echo mode.
        if self.terminal_active && Self::set_terminal_attributes(&self.original).is_ok() {
            self.terminal_active = false;
        }

        self.close_signal_fd();

        if self.signals_blocked {
            // SAFETY: `old_signal_mask` was initialized by the successful
            // SIG_BLOCK operation during construction.
            if unsafe {
                libc::sigprocmask(
                    libc::SIG_SETMASK,
                    &self.old_signal_mask,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                self.signals_blocked = false;
            }
        }
    }

    fn finish(&mut self) -> Result<()> {
        let terminal_error = if self.terminal_active {
            match Self::set_terminal_attributes(&self.original) {
                Ok(()) => {
                    self.terminal_active = false;
                    None
                }
                Err(error) => Some(error),
            }
        } else {
            None
        };

        self.close_signal_fd();

        let signal_error = if self.signals_blocked {
            // SAFETY: `old_signal_mask` was initialized by the successful
            // SIG_BLOCK operation during construction.
            if unsafe {
                libc::sigprocmask(
                    libc::SIG_SETMASK,
                    &self.old_signal_mask,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                self.signals_blocked = false;
                None
            } else {
                Some(io::Error::last_os_error())
            }
        } else {
            None
        };

        if let Some(error) = terminal_error {
            bail!(
                "Terminal Error: Unable to restore terminal settings after PIN entry: {}",
                error
            );
        }
        if let Some(error) = signal_error {
            bail!(
                "Terminal Error: Unable to restore the signal mask after PIN entry: {}",
                error
            );
        }

        Ok(())
    }

    fn direct_read(byte: &mut u8) -> ReadEvent {
        // SAFETY: `byte` points to one writable byte for the one-byte read.
        let count =
            unsafe { libc::read(libc::STDIN_FILENO, byte as *mut u8 as *mut libc::c_void, 1) };
        match count {
            1 => ReadEvent::Byte(*byte),
            0 => ReadEvent::Eof,
            value if value < 0 => {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    ReadEvent::Interrupted
                } else {
                    ReadEvent::Error
                }
            }
            _ => ReadEvent::Error,
        }
    }

    fn read_byte(&self, byte: &mut u8) -> ReadEvent {
        if !self.terminal_active {
            return Self::direct_read(byte);
        }

        loop {
            let mut fds = [
                libc::pollfd {
                    fd: self.signal_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            // SAFETY: `fds` is a live two-element pollfd array for the duration
            // of the blocking call.
            let poll_result =
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if poll_result < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return ReadEvent::Error;
            }

            if (fds[0].revents & libc::POLLIN) != 0 {
                // SAFETY: `signalfd_siginfo` is a plain C structure filled in
                // full by the signalfd read before any field is inspected.
                let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
                // SAFETY: `info` is writable storage of exactly the requested
                // size, and `signal_fd` is owned and open.
                let count = unsafe {
                    libc::read(
                        self.signal_fd,
                        &mut info as *mut libc::signalfd_siginfo as *mut libc::c_void,
                        std::mem::size_of::<libc::signalfd_siginfo>(),
                    )
                };
                if count == std::mem::size_of::<libc::signalfd_siginfo>() as libc::ssize_t {
                    return ReadEvent::Signal(info.ssi_signo as libc::c_int);
                }
                if count < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted
                        || error.kind() == io::ErrorKind::WouldBlock
                    {
                        continue;
                    }
                }
                return ReadEvent::Error;
            }

            if (fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                return ReadEvent::Error;
            }
            if (fds[1].revents & (libc::POLLIN | libc::POLLHUP)) != 0 {
                return Self::direct_read(byte);
            }
            if (fds[1].revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
                return ReadEvent::Error;
            }
        }
    }

    fn forward_signal(&mut self, signal_number: libc::c_int) -> Result<()> {
        // A signal read from signalfd was consumed. Restore terminal state and
        // the original signal mask before re-delivering it.
        self.finish()?;

        // SAFETY: `signal_number` came from signalfd for the guarded signal set.
        if unsafe { libc::raise(signal_number) } != 0 {
            let error = io::Error::last_os_error();
            bail!(
                "PIN Error: Unable to re-deliver interrupt signal: {}",
                error
            );
        }

        // Normally the default signal action does not return. A custom handler
        // may return, or the signal may have been blocked in the original mask.
        bail!("PIN Error: PIN entry interrupted by signal.")
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        self.restore_no_throw();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputAction {
    Finish,
    Added,
    Erased,
    Ignored,
}

fn consume_input_byte(
    ch: u8,
    input: &mut [u8; MAX_PIN_LENGTH],
    input_len: &mut usize,
    input_overflow: &mut bool,
    invalid_input: &mut bool,
) -> InputAction {
    if ch == b'\n' || ch == b'\r' {
        return InputAction::Finish;
    }

    if ch.is_ascii_digit() {
        if *input_len >= input.len() {
            // Sticky: discarded excess digits cannot be undone by backspace.
            *input_overflow = true;
            return InputAction::Ignored;
        }

        input[*input_len] = ch;
        *input_len += 1;
        return InputAction::Added;
    }

    if ch == b'\x08' || ch == b'\x7f' {
        if *input_len == 0 {
            return InputAction::Ignored;
        }

        *input_len -= 1;
        input[*input_len].zeroize();
        return InputAction::Erased;
    }

    *invalid_input = true;
    InputAction::Ignored
}

fn parse_pin(
    input: &[u8],
    input_overflow: bool,
    invalid_input: bool,
    read_error: bool,
) -> Result<u64> {
    if read_error {
        bail!("PIN Error: Failed to read recovery PIN.");
    }
    if invalid_input {
        bail!("PIN Error: Recovery PIN must contain only digits.");
    }
    if input.is_empty() {
        bail!("PIN Error: Recovery PIN is required.");
    }
    if input_overflow
        || input.len() > MAX_PIN_LENGTH
        || (input.len() == MAX_PIN_LENGTH && input > MAX_UINT64_STR.as_slice())
    {
        bail!("PIN Error: Recovery PIN is too long or out of range.");
    }

    let input_str = std::str::from_utf8(input)
        .map_err(|_| anyhow!("PIN Error: Invalid recovery PIN format."))?;
    let result = input_str
        .parse::<u64>()
        .map_err(|_| anyhow!("PIN Error: Invalid recovery PIN format."))?;
    if result == 0 {
        bail!("PIN Error: Invalid recovery PIN format.");
    }

    Ok(result)
}

fn write_stdout_checked(bytes: &[u8], error_message: &'static str) -> Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all(bytes)
        .and_then(|_| stdout.flush())
        .map_err(|_| anyhow!(error_message))
}

/// Read a recovery PIN from stdin using fail-closed Linux terminal handling.
///
/// Format errors are reported separately from wrong-PIN cryptographic failure.
///
/// Fills `out_pin` in place rather than returning the secret by value, so no
/// unwiped copy is left behind in a return slot.
pub fn get_pin(out_pin: &mut Zeroizing<u64>) -> Result<()> {
    // SAFETY: `isatty` only inspects the valid process stdin descriptor.
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    let mut termios_guard = TermiosGuard::new(is_tty)?;

    write_stdout_checked(
        b"\nPIN: ",
        "PIN Error: Failed to display the recovery PIN prompt.",
    )?;

    let mut input = Zeroizing::new([0u8; MAX_PIN_LENGTH]);
    let mut input_len = 0usize;
    let mut input_overflow = false;
    let mut invalid_input = false;
    let mut read_error = false;
    let mut ch = Zeroizing::new(0u8);

    loop {
        match termios_guard.read_byte(&mut ch) {
            ReadEvent::Byte(value) => {
                *ch = value;
                match consume_input_byte(
                    value,
                    &mut input,
                    &mut input_len,
                    &mut input_overflow,
                    &mut invalid_input,
                ) {
                    InputAction::Finish => break,
                    InputAction::Added if termios_guard.masks_input() => {
                        write_stdout_checked(
                            b"*",
                            "PIN Error: Failed to display masked PIN input.",
                        )?;
                    }
                    InputAction::Erased if termios_guard.masks_input() => {
                        write_stdout_checked(
                            b"\x08 \x08",
                            "PIN Error: Failed to display masked PIN input.",
                        )?;
                    }
                    _ => {}
                }
            }
            ReadEvent::Eof => break,
            ReadEvent::Interrupted => continue,
            ReadEvent::Signal(signal_number) => {
                input.zeroize();
                input_len = 0;
                ch.zeroize();
                termios_guard.forward_signal(signal_number)?;
            }
            ReadEvent::Error => {
                read_error = true;
                break;
            }
        }
    }

    write_stdout_checked(b"\n", "PIN Error: Failed to display masked PIN input.")?;
    termios_guard.finish()?;

    let parsed = parse_pin(
        &input[..input_len],
        input_overflow,
        invalid_input,
        read_error,
    );
    input.zeroize();
    ch.zeroize();
    **out_pin = parsed?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_message(result: Result<u64>) -> String {
        result.unwrap_err().to_string()
    }

    #[test]
    fn parser_accepts_full_u64_range() {
        assert_eq!(parse_pin(b"1", false, false, false).unwrap(), 1);
        assert_eq!(
            parse_pin(MAX_UINT64_STR, false, false, false).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn parser_rejects_empty_zero_and_out_of_range() {
        assert_eq!(
            error_message(parse_pin(b"", false, false, false)),
            "PIN Error: Recovery PIN is required."
        );
        assert_eq!(
            error_message(parse_pin(b"0", false, false, false)),
            "PIN Error: Invalid recovery PIN format."
        );
        assert_eq!(
            error_message(parse_pin(b"18446744073709551616", false, false, false)),
            "PIN Error: Recovery PIN is too long or out of range."
        );
    }

    #[test]
    fn parser_reports_read_invalid_and_overflow_states_strictly() {
        assert_eq!(
            error_message(parse_pin(b"12", false, false, true)),
            "PIN Error: Failed to read recovery PIN."
        );
        assert_eq!(
            error_message(parse_pin(b"12", false, true, false)),
            "PIN Error: Recovery PIN must contain only digits."
        );
        assert_eq!(
            error_message(parse_pin(b"12", true, false, false)),
            "PIN Error: Recovery PIN is too long or out of range."
        );
    }

    #[test]
    fn byte_collector_tracks_backspace_invalid_input_and_sticky_overflow() {
        let mut input = [0u8; MAX_PIN_LENGTH];
        let mut input_len = 0usize;
        let mut overflow = false;
        let mut invalid = false;

        assert_eq!(
            consume_input_byte(
                b'7',
                &mut input,
                &mut input_len,
                &mut overflow,
                &mut invalid
            ),
            InputAction::Added
        );
        assert_eq!(
            consume_input_byte(
                b'\x7f',
                &mut input,
                &mut input_len,
                &mut overflow,
                &mut invalid
            ),
            InputAction::Erased
        );
        assert_eq!(input_len, 0);
        assert_eq!(input[0], 0);

        assert_eq!(
            consume_input_byte(
                b'x',
                &mut input,
                &mut input_len,
                &mut overflow,
                &mut invalid
            ),
            InputAction::Ignored
        );
        assert!(invalid);

        for _ in 0..=MAX_PIN_LENGTH {
            consume_input_byte(
                b'9',
                &mut input,
                &mut input_len,
                &mut overflow,
                &mut invalid,
            );
        }
        assert_eq!(input_len, MAX_PIN_LENGTH);
        assert!(overflow);
        consume_input_byte(
            b'\x08',
            &mut input,
            &mut input_len,
            &mut overflow,
            &mut invalid,
        );
        assert!(overflow);
    }

    #[test]
    fn byte_collector_finishes_on_newline_or_carriage_return() {
        for terminator in *b"\n\r" {
            let mut input = [0u8; MAX_PIN_LENGTH];
            let mut input_len = 0usize;
            let mut overflow = false;
            let mut invalid = false;
            assert_eq!(
                consume_input_byte(
                    terminator,
                    &mut input,
                    &mut input_len,
                    &mut overflow,
                    &mut invalid,
                ),
                InputAction::Finish
            );
        }
    }
}
