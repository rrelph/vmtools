//! What --step says (design section 7.1). Written for the people the guides
//! are for: careful, motivated, and not security engineers. Plain words, no
//! acronyms without a gloss, and every check says what a failure would mean.
//!
//! Plain mode prints none of this; it runs the same stages in the same order.

/// Numbered stages in a run that unlocks. A failed check ends the run with
/// an unnumbered notice instead of the last one.
pub const STAGES: usize = 5;

pub const INTRO: &str = "\
Your VM's disk is encrypted, and it cannot start until it gets your disk
passphrase. This tool gives it the passphrase only after the VM has proved,
with a certificate from AMD, exactly what it is and that it is running on a
real AMD confidential-computing processor with its protections on.

The proof matters because the server your VM runs on is not trusted, and
that includes us, the provider. Someone who controls the server could try
to start a copy of your VM with its protections off, or pretend to be your
VM, to catch your passphrase. The checks below catch that.

Nothing secret is sent until every check has passed. You can stop at any
pause with Ctrl-C, and your passphrase stays with you.";

pub const CONNECT: &str = "\
The tool now opens one secure (SSH) connection to your VM's unlock service.
The server carries the connection but cannot read it or change it. Your VM
answers with a key of its own, made fresh this time it started, and the
tool writes down that key. Everything else happens over this same
connection.";

pub const ATTEST: &str = "\
The tool makes up a random number, used once, and asks your VM for a
report about itself that includes it. The VM's AMD processor, not the VM's
software, writes and signs the report. It records what software the VM
started with, the rules it was started under, and a fingerprint of the
random number together with the connection key you just saw.";

pub const VCEK: &str = "\
To check the processor's signature, the tool needs that processor's own
certificate from AMD. It has usually been saved from an earlier unlock. If
not, the tool downloads it from AMD's key server, which tells AMD that
someone is checking a machine with this processor, and nothing more. The
download does not need to be trusted: a wrong certificate fails the checks.";

pub const CHECKS: &str = "\
Now the checks, one at a time. Each says what it looks at, then shows
what the tool expected and what the report says. A single failure stops
the unlock.";

/// A plain title for check `n`, shown in --step mode before its technical
/// name.
pub fn title(n: u8) -> &'static str {
    match n {
        1 => "the processor's certificate is from AMD",
        2 => "the processor signed this report",
        3 => "a report this tool can read",
        4 => "made just now, for this connection",
        5 => "the software your VM started with",
        6 => "the rules your VM was started under",
        7 => "from the most trusted level of your VM",
        8 => "started for your organization",
        9 => "processor firmware is up to date",
        10 => "a processor you have seen before",
        _ => "",
    }
}

/// Before check `n`: what it looks at, and what a failure would mean.
pub fn check(n: u8) -> &'static str {
    match n {
        1 => {
            "\
The report is signed by a key inside your VM's processor, and AMD vouches for
that key with a certificate. This tool carries its own copies of AMD's root
certificates, so it does not depend on anyone handing them over. This check
confirms the processor's certificate really comes from AMD, and that it is
for the exact chip and firmware versions the report names."
        }
        2 => {
            "\
This confirms that processor key signed the report, and that not one bit of
it has changed since. Nobody else can make this signature: not us, and not
anyone who controls the server."
        }
        3 => {
            "\
A basic check that the report is a kind this tool knows how to read."
        }
        4 => {
            "\
The report contains a fingerprint of two things: the random number this tool
made up a moment ago, and the key of the connection you are on now. A match
means the report was made just now, for this attempt, by the very machine at
the other end of this connection. An old report, or one passed along from a
different machine, fails here."
        }
        5 => {
            "\
Before your VM ran anything, the processor measured the software it started
with: its firmware and the small unlock system that is asking for your
passphrase now. This compares that measurement with the one we publish for
the unmodified unlock system. Any change to that software, however small,
gives a different measurement."
        }
        6 => {
            "\
The rules your VM was started under. Debugging must not be allowed, because it
would let the server read and change your VM's memory. A migration agent must
not be allowed, because it could copy your VM out."
        }
        7 => {
            "\
The report must come from the most trusted level inside your VM, where only
the unlock system runs, and not from a less trusted level that could be
running something else."
        }
        8 => {
            "\
Your VM was started with a fingerprint of the certificate authority key that
decides who may unlock it: your organization's. The unlock system itself
refused to start unless the key it was given matches that fingerprint, and
here you check the fingerprint against your own copy of the key. A different
value means the VM was started for someone else's key, and anyone holding
certificates from that key could be the one you are talking to."
        }
        9 => {
            "\
The versions of the processor's firmware and security code. Versions older
than the ones we publish as the minimum, which may have known weaknesses, are
refused."
        }
        10 => {
            "\
Optional: you can limit unlocks to processors you have seen before. You have
not set this up, so any genuine processor is accepted."
        }
        _ => "",
    }
}

pub const PASSED: &str = "\
Every check passed. Your VM has proved it is the unmodified unlock system,
running with its protections on, at the other end of this connection, right
now. The tool will now ask for your disk passphrase and send it over this
same connection. The VM opens your disk and starts its own system.";

pub const FAILED: &str = "\
STOP. At least one check failed, so your passphrase was NOT sent.

Treat this as a security event. It can mean someone is trying to get your
passphrase. Do not run the tool again to see if it works the second time,
and do not give your passphrase any other way. Keep the evidence below, and
contact us and your organization's security contact.";

pub const DONE: &str = "\
Your VM is starting its own system. In a minute or so you can log in as
usual. When you do, SSH must accept your VM's login key without any warning.
If it warns that the key has changed, treat that as a security event too.";
