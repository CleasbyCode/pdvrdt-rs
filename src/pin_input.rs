use crate::pin_codec::{parse_recovery_pin_text, PinParseError, PinPrompt, RecoveryPin};
use anyhow::{anyhow, bail, Result};
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};

/// 24 characters plus 5 group dashes, with room to spare.
const MAX_PIN_KEYSTROKES: usize = 32;

struct TermiosGuard {
    word: &'static str,
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
    fn inactive(word: &'static str) -> Self {
        Self {
            word,
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

    fn new(is_tty: bool, word: &'static str) -> Result<Self> {
        let mut guard = Self::inactive(word);
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
                // Rust normally ignores SIGPIPE, but callers can change its
                // disposition. Protect prompt/masking writes and explicitly
                // delivered SIGPIPE without changing that disposition.
                && libc::sigaddset(&mut guarded_signals, libc::SIGPIPE) == 0
                && libc::sigaddset(&mut guarded_signals, libc::SIGTSTP) == 0
        };
        if !signal_set_ok {
            bail!("Terminal Error: Unable to prepare signal protection for {word} entry.");
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
                "Terminal Error: Unable to protect {} entry from signals: {}",
                word,
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
                "Terminal Error: Unable to monitor signals during {} entry: {}",
                word,
                error
            ));
        }

        // SAFETY: `original` is writable storage for a `termios` value and stdin
        // was established as a TTY by the caller.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut guard.original) } != 0 {
            let error = io::Error::last_os_error();
            return Err(anyhow!(
                "Terminal Error: Unable to read terminal settings for secure {} entry: {}",
                word,
                error
            ));
        }

        let mut raw = guard.original;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        if let Err(error) = Self::set_terminal_attributes(&raw) {
            return Err(anyhow!(
                "Terminal Error: Unable to disable terminal echo for secure {} entry: {}",
                word,
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
                "Terminal Error: Unable to restore terminal settings after {} entry: {}",
                self.word,
                error
            );
        }
        if let Some(error) = signal_error {
            bail!(
                "Terminal Error: Unable to restore the signal mask after {} entry: {}",
                self.word,
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
                "{} Entry Error: Unable to re-deliver interrupt signal: {}",
                self.word,
                error
            );
        }

        // Suspending (Ctrl-Z) deliberately cancels PIN entry rather than resuming
        // it; say so, since the user did not ask for the operation to stop.
        if signal_number == libc::SIGTSTP {
            bail!(
                "{0} Entry Error: {0} entry was cancelled by suspend (Ctrl-Z). Run the command again to enter your {0}.",
                self.word
            );
        }
        // Normally the default signal action does not return. A custom handler
        // may return, or the signal may have been blocked in the original mask.
        bail!(
            "{0} Entry Error: {0} entry interrupted by signal.",
            self.word
        )
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
    AddedDash,
    Erased,
    Ignored,
}

/// Collect one keystroke. Spaces and tabs are ignored, so a KEY pasted with
/// stray whitespace still works. Every other keystroke is kept -- including the
/// group dash, so a backspace removes the dash the user typed, and so a stray
/// character rejects the entry instead of being silently dropped. Keystrokes
/// past the buffer are not stored but are counted, so a backspace undoes the
/// keystroke the user actually made last.
fn consume_input_byte(
    ch: u8,
    input: &mut [u8; MAX_PIN_KEYSTROKES],
    input_len: &mut usize,
    dropped_keys: &mut usize,
) -> InputAction {
    match ch {
        b'\n' | b'\r' => InputAction::Finish,
        b' ' | b'\t' => InputAction::Ignored,
        b'\x08' | b'\x7f' => {
            if *dropped_keys > 0 {
                // Undo an over-limit keystroke; nothing was echoed for it.
                *dropped_keys -= 1;
                InputAction::Ignored
            } else if *input_len > 0 {
                *input_len -= 1;
                input[*input_len].zeroize();
                InputAction::Erased
            } else {
                InputAction::Ignored
            }
        }
        _ if *input_len >= input.len() => {
            *dropped_keys += 1;
            InputAction::Ignored
        }
        _ => {
            input[*input_len] = ch;
            *input_len += 1;
            if ch == b'-' {
                InputAction::AddedDash
            } else {
                InputAction::Added
            }
        }
    }
}

/// Deliberately says nothing about which rule the input broke: the shape of a
/// recovery KEY/PIN is public, but how far a given attempt got is not worth
/// echoing. Each prompt describes only the forms its image can take.
fn format_error(prompt: PinPrompt) -> &'static str {
    match prompt {
        PinPrompt::Key => {
            "KEY Entry Error: That is not a well-formed recovery KEY.\n\n\
             A pdvrdt KEY is 24 letters and digits, printed in groups of four \
             (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX).\n\n\
             Enter it exactly as it was printed when the file was concealed."
        }
        PinPrompt::Pin => {
            "PIN Entry Error: That is not a well-formed recovery PIN.\n\n\
             This image was made before pdvrdt 6.0 and uses a PIN of up to 20 digits.\n\n\
             Enter it exactly as it was printed when the file was concealed."
        }
        PinPrompt::KeyOrPin => {
            "KEY/PIN Entry Error: That is not a well-formed recovery KEY/PIN.\n\n\
             A pdvrdt KEY is 24 letters and digits, printed in groups of four \
             (XXXX-XXXX-XXXX-XXXX-XXXX-XXXX);\n\
             Images made before pdvrdt 6.0 use a PIN of up to 20 digits.\n\n\
             Enter it exactly as it was printed when the file was concealed."
        }
    }
}

/// A 24-character KEY whose check pair does not match its body: a typo the
/// user can find, reported before any key derivation. An image made before 6.0
/// takes no KEY at all, so there the entry is simply not a well-formed PIN.
fn check_error(prompt: PinPrompt) -> &'static str {
    match prompt {
        PinPrompt::Key => {
            "KEY Entry Error: That KEY has a typo: its last two characters do not \
             match the rest. Check each character, including upper and lower case."
        }
        PinPrompt::Pin => format_error(prompt),
        PinPrompt::KeyOrPin => {
            "KEY/PIN Entry Error: That KEY has a typo: its last two characters do not \
             match the rest. Check each character, including upper and lower case."
        }
    }
}

/// Knowable mistakes are reported before an Argon2id run that could only end
/// in the ambiguous "invalid KEY/PIN or file is corrupt". The codec owns the
/// grammar (old decimal PIN, or 24-character KEY with a check pair).
fn parse_entry(
    input: &[u8],
    dropped_keys: usize,
    read_error: bool,
    prompt: PinPrompt,
    out_pin: &mut RecoveryPin,
) -> Result<()> {
    out_pin.clear();
    if read_error {
        bail!(
            "{0} Entry Error: Failed to read recovery {0}.",
            prompt.word()
        );
    }
    if dropped_keys > 0 {
        bail!("{}", format_error(prompt));
    }
    match parse_recovery_pin_text(input, out_pin) {
        Ok(()) => Ok(()),
        Err(PinParseError::Checksum) => bail!("{}", check_error(prompt)),
        Err(PinParseError::Malformed) => bail!("{}", format_error(prompt)),
    }
}

fn write_stdout_checked(bytes: &[u8], error_message: &str) -> Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all(bytes)
        .and_then(|_| stdout.flush())
        .map_err(|_| anyhow!("{error_message}"))
}

/// Read a recovery KEY or PIN from stdin using fail-closed Linux terminal
/// handling, with `prompt` naming what the image takes. Format errors and KEY
/// typos are reported separately from a wrong-secret cryptographic failure.
///
/// Fills `out_pin` in place rather than returning the secret by value, so no
/// unwiped copy is left behind in a return slot.
pub fn get_pin(prompt: PinPrompt, out_pin: &mut RecoveryPin) -> Result<()> {
    let word = prompt.word();
    out_pin.clear();
    // SAFETY: `isatty` only inspects the valid process stdin descriptor.
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) != 0 };
    let mut termios_guard = TermiosGuard::new(is_tty, word)?;

    let display_error = format!("{word} Entry Error: Failed to display masked {word} input.");
    write_stdout_checked(
        format!("\n{word}: ").as_bytes(),
        &format!("{word} Entry Error: Failed to display the recovery {word} prompt."),
    )?;

    let mut input = Zeroizing::new([0u8; MAX_PIN_KEYSTROKES]);
    let mut input_len = 0usize;
    let mut dropped_keys = 0usize;
    let mut read_error = false;
    let mut ch = Zeroizing::new(0u8);

    loop {
        match termios_guard.read_byte(&mut ch) {
            ReadEvent::Byte(value) => {
                *ch = value;
                let action =
                    consume_input_byte(value, &mut input, &mut input_len, &mut dropped_keys);
                if !termios_guard.masks_input() {
                    if action == InputAction::Finish {
                        break;
                    }
                    continue;
                }
                match action {
                    InputAction::Finish => break,
                    // Dashes are layout, not secret; echoing them keeps the
                    // user's place in the groups.
                    InputAction::AddedDash => write_stdout_checked(b"-", &display_error)?,
                    InputAction::Added => write_stdout_checked(b"*", &display_error)?,
                    InputAction::Erased => write_stdout_checked(b"\x08 \x08", &display_error)?,
                    InputAction::Ignored => {}
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

    write_stdout_checked(b"\n", &display_error)?;
    termios_guard.finish()?;

    let parsed = parse_entry(
        &input[..input_len],
        dropped_keys,
        read_error,
        prompt,
        out_pin,
    );
    input.zeroize();
    ch.zeroize();
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(bytes: &[u8]) -> ([u8; MAX_PIN_KEYSTROKES], usize, usize) {
        let mut input = [0u8; MAX_PIN_KEYSTROKES];
        let mut input_len = 0usize;
        let mut dropped = 0usize;
        for &b in bytes {
            if consume_input_byte(b, &mut input, &mut input_len, &mut dropped)
                == InputAction::Finish
            {
                break;
            }
        }
        (input, input_len, dropped)
    }

    fn entry_error(text: &[u8], dropped: usize, prompt: PinPrompt) -> String {
        let mut pin = RecoveryPin::default();
        parse_entry(text, dropped, false, prompt, &mut pin)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn collector_keeps_dashes_skips_spaces_and_stops_at_newline() {
        let (input, len, dropped) = collect(b"112d -rXXU\t-ifSr-RnXL-GbXg-8Eyf\nignored");
        assert_eq!(&input[..len], b"112d-rXXU-ifSr-RnXL-GbXg-8Eyf");
        assert_eq!(dropped, 0);
        for terminator in *b"\n\r" {
            let (_, len, _) = collect(&[b'1', terminator, b'2']);
            assert_eq!(len, 1);
        }
    }

    #[test]
    fn collector_backspace_undoes_the_last_keystroke_including_dropped_ones() {
        let (input, len, _) = collect(b"12-\x7f3");
        assert_eq!(&input[..len], b"123");
        let mut long = vec![b'9'; MAX_PIN_KEYSTROKES + 2];
        let (_, len, dropped) = collect(&long);
        assert_eq!((len, dropped), (MAX_PIN_KEYSTROKES, 2));
        long.extend_from_slice(b"\x08\x08\x08");
        let (input, len, dropped) = collect(&long);
        assert_eq!((len, dropped), (MAX_PIN_KEYSTROKES - 1, 0));
        assert_eq!(input[len], 0);
    }

    #[test]
    fn entries_parse_or_report_by_prompt() {
        let mut pin = RecoveryPin::default();
        parse_entry(
            b"112d-rXXU-ifSr-RnXL-GbXg-8Eyf",
            0,
            false,
            PinPrompt::Key,
            &mut pin,
        )
        .unwrap();
        assert!(pin.is_key());
        parse_entry(b"18446744073709551615", 0, false, PinPrompt::Pin, &mut pin).unwrap();
        assert!(!pin.is_key() && pin.legacy_value == u64::MAX);

        let typo = b"112d-rXXU-ifSr-RnXL-GbXg-8Eyg";
        assert!(entry_error(typo, 0, PinPrompt::Key)
            .starts_with("KEY Entry Error: That KEY has a typo"));
        assert!(entry_error(typo, 0, PinPrompt::KeyOrPin)
            .starts_with("KEY/PIN Entry Error: That KEY has a typo"));
        assert!(entry_error(typo, 0, PinPrompt::Pin)
            .starts_with("PIN Entry Error: That is not a well-formed"));
        assert!(entry_error(b"12a4", 0, PinPrompt::Pin).contains("before pdvrdt 6.0"));
        assert!(entry_error(b"", 0, PinPrompt::Key)
            .starts_with("KEY Entry Error: That is not a well-formed"));
        assert!(entry_error(b"1", 1, PinPrompt::KeyOrPin).starts_with("KEY/PIN Entry Error"));

        let mut pin = RecoveryPin::default();
        let err = parse_entry(b"1", 0, true, PinPrompt::Key, &mut pin)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "KEY Entry Error: Failed to read recovery KEY.");
    }
}
