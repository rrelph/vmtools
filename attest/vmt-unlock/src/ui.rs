//! The one place vmt-unlock talks to the person running it. Plain and --step
//! mode go through the same calls, so they run the same stages in the same
//! order; --step only adds the explanations and the pauses.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use snp::verify::{Check, Outcome};

use crate::explain;

pub struct Ui {
    pub step: bool,
    stage: usize,
}

impl Ui {
    pub fn new(step: bool) -> Ui {
        Ui { step, stage: 0 }
    }

    /// A line of progress, in both modes.
    pub fn say(&self, m: &str) {
        println!("vmt-unlock: {m}");
    }

    /// The start of a stage. In --step mode: a heading, what is about to
    /// happen, and a pause before it does.
    pub fn stage(&mut self, title: &str, text: &str) {
        self.stage += 1;
        if self.step {
            println!();
            println!("=== Stage {} of {}: {title} ===", self.stage, explain::STAGES);
            println!();
            println!("{text}");
            pause();
        }
    }

    /// An unnumbered notice, in --step mode only: a failure, never a stage.
    pub fn alert(&self, title: &str, text: &str) {
        if self.step {
            println!();
            println!("=== {title} ===");
            println!();
            println!("{text}");
        }
    }

    /// Text shown only in --step mode, without a pause.
    pub fn note(&self, text: &str) {
        if self.step {
            println!();
            println!("{text}");
        }
    }

    /// The checks that ran, numbered and counted among themselves. A check
    /// the owner has not set up (the chip_id allowlist, without --chip-id)
    /// does not run, and is neither shown nor counted.
    pub fn checks(&self, all: &[Check]) {
        let ran: Vec<&Check> = all.iter().filter(|c| !matches!(c.outcome, Outcome::Skip(_))).collect();
        for (i, c) in ran.iter().enumerate() {
            self.check(i + 1, ran.len(), c);
        }
    }

    /// One check. Plain: its result and the values compared. --step: first
    /// what it is and why it matters, then a pause, then the same result.
    fn check(&self, i: usize, n: usize, c: &Check) {
        if self.step {
            println!();
            println!("--- Check {i} of {n}: {} ({}) ---", explain::title(c.number), c.name);
            println!();
            println!("{}", explain::check(c.number));
            pause();
        }
        let (tag, why) = match &c.outcome {
            Outcome::Pass => ("PASS", String::new()),
            Outcome::Fail(w) => ("FAIL", format!(": {w}")),
            Outcome::Skip(w) => ("SKIP", format!(": {w}")),
        };
        println!("  [{tag}] {i:>2}. {}{why}", c.name);
        for line in c.detail.lines() {
            println!("          {line}");
        }
    }
}

/// Set once a pause has read end of input: there is no keyboard, and a
/// terminal gives end of input only once, so waiting again would hang.
static NO_KEYBOARD: AtomicBool = AtomicBool::new(false);

/// Wait for Enter. With no keyboard to read (end of input), carry on: an
/// unattended --step run is plain mode with explanations, never a hang.
fn pause() {
    println!();
    print!("Press Enter to continue, or Ctrl-C to stop. ");
    let _ = io::stdout().flush();
    if NO_KEYBOARD.load(Ordering::SeqCst) {
        println!("(no keyboard input: continuing)");
        return;
    }
    let mut line = String::new();
    let read = match File::open("/dev/tty") {
        Ok(tty) => BufReader::new(tty).read_line(&mut line),
        Err(_) => io::stdin().lock().read_line(&mut line),
    };
    if matches!(read, Ok(0) | Err(_)) {
        NO_KEYBOARD.store(true, Ordering::SeqCst);
        println!("(no keyboard input: continuing)");
    }
}

// --- the passphrase prompt ---------------------------------------------------

static ECHO_OFF: AtomicBool = AtomicBool::new(false);
static mut SAVED: Option<libc::termios> = None;

extern "C" fn restore_and_exit(sig: libc::c_int) {
    // Only async-signal-safe calls: tcsetattr, write, signal, raise.
    if ECHO_OFF.load(Ordering::SeqCst) {
        // SAFETY: SAVED is written once, before ECHO_OFF is set, and not
        // again while it is set.
        unsafe {
            if let Some(t) = (*std::ptr::addr_of!(SAVED)).as_ref() {
                let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR);
                if fd >= 0 {
                    libc::tcsetattr(fd, libc::TCSANOW, t);
                    libc::write(fd, b"\n".as_ptr().cast(), 1);
                }
            }
        }
    }
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Ask for the disk passphrase on the terminal, without echoing it. The
/// terminal is put back as it was however the prompt ends, Ctrl-C included.
pub fn read_passphrase(prompt: &str) -> Result<Vec<u8>, String> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("no terminal to ask for the passphrase on ({e}); see --key-file"))?;
    use std::os::fd::AsRawFd;
    let fd = tty.as_raw_fd();
    // SAFETY: plain termios calls on a descriptor we own.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return Err("cannot read the terminal's settings".into());
        }
        *std::ptr::addr_of_mut!(SAVED) = Some(t);
        ECHO_OFF.store(true, Ordering::SeqCst);
        libc::signal(libc::SIGINT, restore_and_exit as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, restore_and_exit as *const () as libc::sighandler_t);
        let mut quiet = t;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ICANON | libc::ECHONL;
        libc::tcsetattr(fd, libc::TCSANOW, &quiet);
    }
    let mut w = &tty;
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = String::new();
    let r = BufReader::new(&tty).read_line(&mut line);
    // SAFETY: as above; SAVED holds the settings read before.
    unsafe {
        if let Some(t) = (*std::ptr::addr_of!(SAVED)).as_ref() {
            libc::tcsetattr(fd, libc::TCSANOW, t);
        }
        ECHO_OFF.store(false, Ordering::SeqCst);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
    r.map_err(|e| format!("reading the passphrase: {e}"))?;
    // The line ending is the Enter key, not part of the passphrase.
    let pass = line.strip_suffix('\n').unwrap_or(&line);
    let pass = pass.strip_suffix('\r').unwrap_or(pass);
    let out = pass.as_bytes().to_vec();
    // SAFETY: zeroes are valid UTF-8.
    unsafe { line.as_bytes_mut().fill(0) };
    if out.is_empty() {
        return Err("no passphrase entered".into());
    }
    Ok(out)
}
