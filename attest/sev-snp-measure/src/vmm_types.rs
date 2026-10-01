//! Python: `vmm_types.py`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmmType {
    Qemu,
    Ec2,
    Gce,
}

impl VmmType {
    /// The names `--vmm-type` accepts, exactly as the Python enum spells
    /// them (case-sensitive).
    pub const NAMES: [&'static str; 3] = ["QEMU", "ec2", "gce"];

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "QEMU" => Some(VmmType::Qemu),
            "ec2" => Some(VmmType::Ec2),
            "gce" => Some(VmmType::Gce),
            _ => None,
        }
    }
}
