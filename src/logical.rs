#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum X86Register {
    EAX = 0,
    ECX = 1,
    EDX = 2,
    EBX = 3,
    ESP = 4,
    EBP = 5,
    ESI = 6,
    EDI = 7,
}

impl X86Register {
    pub const REGNUM_SET: [X86Register; 8] = [
        Self::EAX,
        Self::ECX,
        Self::EDX,
        Self::EBX,
        Self::ESP,
        Self::EBP,
        Self::ESI,
        Self::EDI,
    ];

    pub const fn reg_number(self) -> u8 {
        match self {
            Self::EAX => 0,
            Self::ECX => 1,
            Self::EDX => 2,
            Self::EBX => 3,
            Self::ESP => 4,
            Self::EBP => 5,
            Self::ESI => 6,
            Self::EDI => 7,
        }
    }

    pub fn from_number(n: u8) -> Option<Self> {
        let ret = match n {
            0 => Self::EAX,
            1 => Self::ECX,
            2 => Self::EDX,
            3 => Self::EBX,
            4 => Self::ESP,
            5 => Self::EBP,
            6 => Self::ESI,
            7 => Self::EDI,
            _ => return None,
        };
        Some(ret)
    }
}

#[test]
fn can_cast() {
    let a: Vec<_> = X86Register::REGNUM_SET.iter().map(|&x| x as u8).collect();
    let b: Vec<_> = (0..=7).collect();
    assert_eq!(a, b);
}

#[test]
fn all_eq() {
    for &reg in &X86Register::REGNUM_SET {
        assert_eq!(reg.reg_number(), reg as u8, "reg = {:?}", reg);
    }
}
