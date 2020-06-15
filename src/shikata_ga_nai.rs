use crate::logical::X86Register;
use crate::{
    encoder::{
        BadGenerateError, DecoderStub, Encoder, EncoderBase, EncoderInherit, EncoderOptions,
        XorAdditiveFeedback,
    },
    logical_arena::{Context, GenerateError, PermInner, Writer},
    rex,
    smol_set::SmolSet,
};
use bstr::ByteSlice;
use rand::Rng;
use std::array;

pub struct ShikataGaNai {
    base: XorAdditiveFeedback<Self>,
    options: EncoderOptions,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DecoderStubError {
    #[error("")]
    GenerateError(#[from] GenerateError),
    #[error("")]
    BadGenerateError(#[from] BadGenerateError),
}

impl EncoderInherit<Self> for ShikataGaNai {
    inherit!(XorAdditiveFeedback<Self>);
}

impl Encoder for ShikataGaNai {
    const NAME: &'static str = "Polymorphic XOR Additive Feedback Encoder";
    const DECODER_KEY_SIZE: usize = 4;
    const DECODER_BLOCK_SIZE: usize = 4;

    type PrependBuf = array::IntoIter<u8, 0>;
    fn prepend_buf() -> Self::PrependBuf {
        array::IntoIter::new([])
    }
    type DecoderStubError = DecoderStubError;

    /// Generates the shikata decoder stub.
    fn decoder_stub<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        buf: &mut Vec<u8>,
        badchars: &[u8],
    ) -> Result<DecoderStub, Self::DecoderStubError> {
        // # Shikata will only cut off the last 1-4 bytes of it's own end
        // # depending on the alignment of the original buffer

        if !(Self::modified_registers() & self.saved_registers()).is_empty() {
            return Err(DecoderStubError::BadGenerateError(BadGenerateError));
        }

        let cutoff = 4 - (buf.len() & 3);
        let length = buf.len() + cutoff;
        let mut block = self.generate_shikata_block(rng, badchars, length, cutoff)?;

        // # Set the state specific key offset to wherever the XORK ended up.
        let decoder_key_offset = block.as_bstr().find(b"XORK").expect("Could not find XORK");

        // # Take the last 1-4 bytes of shikata and prepend them to the buffer
        // # that is going to be encoded to make it align on a 4-byte boundary.
        let range = (block.len() - cutoff)..(block.len());
        drop(buf.splice(..0, block.drain(range)));

        Ok(DecoderStub {
            block,
            decoder_key_offset: Some(decoder_key_offset),
        })
    }
}

impl ShikataGaNai {
    pub fn new() -> EncoderBase<Self> {
        EncoderBase::new(Self {
            base: XorAdditiveFeedback::new(),
            options: EncoderOptions::default(),
        })
    }

    /// Returns a polymorphic decoder stub that is capable of decoding a buffer
    /// of the supplied length and encodes the last cutoff bytes of itself.
    fn generate_shikata_block<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        badchars: &[u8],
        mut length: usize,
        cutoff: usize,
    ) -> Result<Vec<u8>, GenerateError> {
        use X86Register::*;

        ph!(xor, add, sub4, add4, xor1, xor2, add1, add2);
        let mut context = Context::new();

        // # Declare logical registers
        let _stack_reg = context.add_reg("stack", ESP);
        let _count_reg = context.add_reg("count", ECX);
        let addr_reg = context.add_reg("addr", None);
        let key_reg = context.add_reg("key", None);

        // # Declare individual blocks
        let endb = context.end_block();

        // # Clear the counter register
        let clear_register = context.add_block(
            "clear_register",
            vec![
                p![_, b"\x31\xc9"], // xor ecx,ecx
                p![_, b"\x29\xc9"], // sub ecx,ecx
                p![_, b"\x33\xc9"], // xor ecx,ecx
                p![_, b"\x2b\xc9"], // sub ecx,ecx
            ],
        );

        // # Divide the length by four but ensure that it aligns on a block size
        // # boundary (4 byte).
        length += (4 + (4 - (length & 3))) & 3;
        length /= 4;

        let p = if length <= 255 {
            c![b"\xb1" + (length as u8)]
        } else if length <= 65536 {
            c![b"\x66\xb9" + (length as u16).to_le_bytes()]
        } else {
            c![b"\xb9" + (length as u32).to_le_bytes()]
        };

        // # Initialize the counter after zeroing it
        let init_counter = context.add_block("init_counter", vec![PermInner::V(p)]);

        // # Key initialization block
        let init_key = context.add_block(
            "init_key",
            vec![p![b, [0xb8 + b.regnum_of(key_reg)?], b"XORK"]],
        );

        ph! { |b|
            xor = [b"\x31", [0x40 + b.regnum_of(addr_reg)? + (8 * b.regnum_of(key_reg)?)]];
            add = [b"\x03", [0x40 + b.regnum_of(addr_reg)? + (8 * b.regnum_of(key_reg)?)]];

            sub4 = [sub_immediate(b.regnum_of(addr_reg)?, -4)];
            add4 = [add_immediate(b.regnum_of(addr_reg)?, 4)];
        }

        // # FPU blocks
        let t: Vec<_> = Self::fpu_instructions()
            .iter()
            .map(|x| PermInner::S(x))
            .collect();
        let fpu = context.add_block("fpu", t);

        let fnstenv = context.add_block("fnstenv", vec![p![_, b"\xd9\x74\x24\xf4"]]);

        context.depends_on(fnstenv, fpu);

        // # Get EIP off the stack
        let getpc = context.add_block("getpc", vec![p![b, [0x58 + b.regnum_of(addr_reg)?]]]);
        context.depends_on(getpc, fnstenv);

        // # Subtract the offset of the fpu instruction since that's where eip points after fnstenv
        ph! { |b|
            xor1 = [xor, [(b.offset_of(endb) - b.offset_of(fpu) - cutoff) as u8]];
            xor2 = [xor, [(b.offset_of(endb) - b.offset_of(fpu) - 4 - cutoff) as u8]];
            add1 = [add, [(b.offset_of(endb) - b.offset_of(fpu) - cutoff) as u8]];
            add2 = [add, [(b.offset_of(endb) - b.offset_of(fpu) - 4 - cutoff) as u8]];
        };

        // # Decoder loop block
        let mut loop_block = context.add_block("loop_block", vec![]);

        let t = vec![
            p![_ | "1", xor1, add1, sub4],
            p![_ | "2", xor1, sub4, add2],
            p![_ | "3", sub4, xor2, add2],
            p![_ | "4", xor1, add1, add4],
            p![_ | "5", xor1, add4, add2],
            p![_ | "6", add4, xor2, add2],
        ];

        loop_block.add_perms(&mut context, t);

        let loop_inst = context.add_block("loop_inst", vec![p![_, b"\xe2\xf5"]]);

        context.depends_on(clear_register, getpc);
        context.depends_on(init_counter, clear_register);
        context.depends_on(loop_block, init_counter);
        context.depends_on(loop_block, init_key);
        context.depends_on(loop_inst, loop_block);

        // # Generate a permutation saving the ECX, ESP, and user defined registers
        context.generate(rng, &self.block_generator_register_blacklist(), badchars)
    }

    /// Always blacklist these registers in our block generation
    fn block_generator_register_blacklist(&self) -> SmolSet<X86Register> {
        const RET: SmolSet<X86Register> =
            SmolSet::<X86Register>::from_slice(&[X86Register::ESP, X86Register::ECX]);
        RET | self.saved_registers()
    }

    /// Returns the set of FPU instructions that can be used for the FPU block of
    /// the decoder stub.
    fn fpu_instructions() -> &'static [[u8; 2]] {
        rex::arch::x86::fpu_instructions()
    }

    /// A list of registers always touched by this encoder
    fn modified_registers() -> SmolSet<X86Register> {
        SmolSet::from_slice(&[
            // The counter register is hardcoded
            X86Register::ECX,
            // These are modified by div and mul operations
            X86Register::EAX,
            X86Register::EDX,
        ])
    }

    /// Convert the `SaveRegisters` to an array of x86 register constants
    fn saved_registers(&self) -> SmolSet<X86Register> {
        self.options.saved_registers.clone()
    }
}

fn sub_immediate(regnum: u8, imm: i32) -> PermInner<'static> {
    if imm == 0 {
        return p![];
    }
    if imm > 255 || imm < -255 {
        p![_, b"\x81", [(0xe8 + regnum)], imm.to_le_bytes()]
    } else {
        p![_, b"\x83", [(0xe8 + regnum)], (imm as u8).to_le_bytes()]
    }
}

fn add_immediate(regnum: u8, imm: i32) -> Vec<u8> {
    if imm == 0 {
        return c![];
    }
    if imm > 255 || imm < -255 {
        c![b"\x81" + [(0xc0 + regnum)] + imm.to_le_bytes()]
    } else {
        c![b"\x83" + [(0xc0 + regnum)] + (imm as u8).to_le_bytes()]
    }
}
