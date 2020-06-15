use crate::encoder::{
    DecoderStub, Encoder, EncoderBase, EncoderInherit, EncoderInheritBase, EncoderOptions,
};
use rand::{prelude::SliceRandom, Rng};
use std::{
    array,
    cell::{Cell, RefCell},
};

pub struct AddSub {
    state: RefCell<AddSubState>,
    z1: Cell<u32>,
    z2: Cell<u32>,
    options: EncoderOptions,
}

#[derive(Debug)]
struct AddSubState {
    data: Vec<u8>,
    inst: Instructions,
    avchars: Vec<u8>,
    set: AddOrSub,
}

impl Default for AddSubState {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            inst: Instructions::default(),
            avchars: Vec::new(),
            set: AddOrSub::Add,
        }
    }
}

#[derive(Debug, Default)]
struct Instructions {
    opcode: u8,
    push: u8,
    pop: u8,
    and: u8,
    push_esp: u8,
    pop_esp: u8,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AddOrSub {
    Add = 1,
    Sub = 2,
}

#[test]
fn size() {
    assert!(std::mem::size_of::<Option<AddOrSub>>() == 1);
}

impl AddSub {
    pub fn new() -> EncoderBase<Self> {
        EncoderBase::new(Self {
            state: RefCell::new(AddSubState::default()),
            z1: Cell::new(0),
            z2: Cell::new(0),
            options: EncoderOptions::default(),
        })
    }

    fn add_or_sub(avchars: &[u8]) -> Option<AddOrSub> {
        let add = [0x05, 0x50, 0x58, 0x25, 0x54, 0x5C];
        let sub = [0x2D, 0x50, 0x58, 0x25, 0x54, 0x5C];
        if add.iter().all(|ch| avchars.contains(ch)) {
            Some(AddOrSub::Add)
        } else if sub.iter().all(|ch| avchars.contains(ch)) {
            Some(AddOrSub::Sub)
        } else {
            None
        }
    }

    fn write_inst(data: &mut Vec<u8>, inst: u8, mut mcode: u32) {
        data.push(inst);
        if mcode != 0 {
            for _ in 0..4 {
                let t = mcode as u8;
                data.push(t);
                mcode >>= 8;
            }
        }
    }

    fn rand_with_av_chars<R: Rng + ?Sized>(rng: &mut R, avchars: &[u8]) -> u32 {
        let mut t2 = 0;
        for _ in 0..4 {
            let &c = avchars.choose(rng).unwrap();
            t2 <<= 8;
            t2 += u32::from(c);
        }
        t2
    }

    fn check_non_av_chars(avchars: &[u8], mut target: u32) -> bool {
        for _ in 0..4 {
            let t = target as u8;
            if !avchars.contains(&t) {
                return true;
            }
            target >>= 8;
        }
        false
    }

    fn encode_inst<R: Rng + ?Sized>(rng: &mut R, state: &mut AddSubState, target: u32) {
        let AddSubState {
            data,
            inst,
            avchars,
            set,
        } = state;

        let mut a;
        let mut b;
        let mut c;
        while {
            a = Self::rand_with_av_chars(rng, avchars);
            b = Self::rand_with_av_chars(rng, avchars);
            match set {
                AddOrSub::Add => {
                    c = target - a - b;
                }
                AddOrSub::Sub => {
                    c = 0 - target - a - b;
                }
            }
            Self::check_non_av_chars(avchars, c)
        } {}
        Self::write_inst(data, inst.opcode, a);
        Self::write_inst(data, inst.opcode, b);
        Self::write_inst(data, inst.opcode, c);
    }
    fn encode_shellcode<R: Rng + ?Sized>(
        rng: &mut R,
        state: &mut AddSubState,
        target: u32,
        z1: u32,
        z2: u32,
    ) {
        Self::write_inst(&mut state.data, state.inst.and, z1);
        Self::write_inst(&mut state.data, state.inst.and, z2);
        Self::encode_inst(rng, state, target);
        Self::write_inst(&mut state.data, state.inst.push, 0);
    }
    fn buffer_offset(&self) -> Option<u32> {
        self.options.buffer_offset
    }
}

impl EncoderInherit<Self> for AddSub {
    inherit!(@find_key @find_bad_keys EncoderInheritBase<Self>);

    fn encode_block<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        key: &mut u32,
        block: &[u8],
        badchars: &[u8],
    ) -> Vec<u8> {
        let _ = (key, badchars);

        // # encoding shellcode
        {
            self.state.borrow_mut().data.clear();
        }
        let target = block;
        if target.len() < 4 {
            return Vec::new();
        }
        let mut t = 0;
        for i in 0..3 {
            let t1 = target[3 - i];
            t <<= 8;
            t += u32::from(t1);
        }

        Self::encode_shellcode(
            rng,
            &mut self.state.borrow_mut(),
            t,
            self.z1.get(),
            self.z2.get(),
        );

        self.state.borrow_mut().data.clone()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AddSubError {
    #[error("Bad character list includes essential characters.")]
    BadCharsIncludesEssential,
    #[error("Shellcode size must be divisible by 4, try nop padding.")]
    ShellcodeNotDivByFour,
}

impl Encoder for AddSub {
    const NAME: &'static str = "Add/Sub Encoder";
    const DECODER_KEY_SIZE: usize = 0;
    const DECODER_BLOCK_SIZE: usize = 4;
    type PrependBuf = array::IntoIter<u8, 0>;
    fn prepend_buf() -> Self::PrependBuf {
        array::IntoIter::new([])
    }
    type DecoderStubError = AddSubError;
    fn decoder_stub<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        buf: &mut Vec<u8>,
        badchars: &[u8],
    ) -> Result<DecoderStub, Self::DecoderStubError> {
        *buf = buf.rchunks(4).flatten().copied().collect();

        let mut data = Vec::new();
        let avchars: Vec<_> = (0..=255).filter(|i| !badchars.contains(i)).collect();
        let offset = self.buffer_offset().unwrap_or(0);
        let set = Self::add_or_sub(&avchars);

        let set = set.ok_or(AddSubError::BadCharsIncludesEssential)?;

        let opcode = match set {
            AddOrSub::Add => 0x05,
            AddOrSub::Sub => 0x2d,
        };

        let inst = Instructions {
            opcode,
            push: 0x50,
            pop: 0x58,
            and: 0x25,
            push_esp: 0x54,
            pop_esp: 0x5c,
        };

        if buf.len() % 4 != 0 {
            return Err(AddSubError::ShellcodeNotDivByFour);
        }
        // # init
        Self::write_inst(&mut data, inst.push_esp, 0);
        Self::write_inst(&mut data, inst.pop, 0);
        let mut state = AddSubState {
            data: data.clone(),
            inst,
            avchars,
            set,
        };
        Self::encode_inst(rng, &mut state, offset);
        Self::write_inst(&mut data, state.inst.push, 0);
        Self::write_inst(&mut data, state.inst.pop_esp, 0);
        // # zeroing registers
        let mut z1;
        let mut z2;
        while {
            z1 = Self::rand_with_av_chars(rng, &state.avchars);
            z2 = Self::rand_with_av_chars(rng, &state.avchars);
            z1 & z2 != 0
        } {}
        self.z1.set(z1);
        self.z2.set(z2);

        *self.state.borrow_mut() = state;

        Ok(DecoderStub {
            block: data,
            decoder_key_offset: None,
        })
    }
}
