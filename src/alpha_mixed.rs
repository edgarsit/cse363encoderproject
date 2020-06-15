use crate::{
    encoder::{Alphanum, DecoderStub, Encoder, EncoderInherit, EncoderOptions, EncoderState, EncoderBase},
    logical::X86Register,
    rex,
    smol_set::SmolSet,
};
use rand::Rng;
use rex::{arch::x86::geteip_fpu, encoder::alpha2::alpha_mixed::GenDecoderPrefixError};
use std::{array, error};

pub struct AlphaMixed {
    base: Alphanum<Self>,
    options: EncoderOptions,
}

impl EncoderInherit<Self> for AlphaMixed {
    inherit!(@find_key @find_bad_keys Alphanum<Self>);

    /// Encodes a one byte block with the current index of the length of the
    /// payload.
    fn encode_block<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        key: &mut u32,
        block: &[u8],
        badchars: &[u8],
    ) -> Vec<u8> {
        let _ = key;
        assert!(block.len() == Self::DECODER_BLOCK_SIZE);
        rex::encoder::alpha2::alpha_mixed::encode_byte(rng, block[0], badchars).unwrap()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum AlphaMixedEncoderError {
    #[error("Unable to generate geteip code")]
    Encoding,
    #[error("BadGenerateError")]
    BadGenerate,
    #[error("{0}")]
    GenDecoderPrefix(#[from] GenDecoderPrefixError),
}

impl Encoder for AlphaMixed {
    const NAME: &'static str = "Add/Sub Encoder";
    const DECODER_KEY_SIZE: usize = 0;
    const DECODER_BLOCK_SIZE: usize = 1;
    type PrependBuf = array::IntoIter<u8, 0>;
    fn prepend_buf() -> Self::PrependBuf {
        array::IntoIter::new([])
    }
    type DecoderStubError = AlphaMixedEncoderError;
    fn decoder_stub<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        buf: &mut Vec<u8>,
        badchars: &[u8],
    ) -> Result<DecoderStub, Self::DecoderStubError> {
        let _ = buf;
        let mut modified_registers = SmolSet::new();
        let reg = self.base.buffer_register;
        let mut off = self.base.buffer_offset.unwrap_or(0);
        let mut buf = vec![];
        let reg = match reg {
            Some(reg) => reg,
            None => {
                if self.base.allow_win32_seh {
                    buf = b"VTX630VXH49HHHPhYAAQhZYYYYAAQQDDDd36FFFFTXVj0PPTUPPa301089".to_vec();
                    off = 0;
                    modified_registers.extend(&[
                        X86Register::ESP,
                        X86Register::EDI,
                        X86Register::ESI,
                        X86Register::EBP,
                        X86Register::EBX,
                        X86Register::EDX,
                        X86Register::ECX,
                        X86Register::EAX,
                    ]);
                    X86Register::ECX
                } else {
                    let res = geteip_fpu(rng, badchars, &mut modified_registers)
                        .ok_or(AlphaMixedEncoderError::Encoding)?;

                    let (buf_, reg_, off_) = res;
                    buf = buf_;
                    off = off_;
                    reg_
                }
            }
        };

        buf.extend_from_slice(&rex::encoder::alpha2::alpha_mixed::gen_decoder(
            reg,
            off,
            &mut modified_registers,
        )?);
        let stub = buf;

        if !(modified_registers & self.saved_registers()).is_empty() {
            return Err(AlphaMixedEncoderError::BadGenerate);
        }

        Ok(DecoderStub {
            block: stub,
            decoder_key_offset: None,
        })
    }
    /// Tack on our terminator
    fn encode_end(state: &mut EncoderState) -> Result<(), Box<dyn error::Error>> {
        state
            .encoded
            .extend_from_slice(&rex::encoder::alpha2::alpha_mixed::add_terminator());
        Ok(())
    }
}

impl AlphaMixed {
    pub fn new() -> EncoderBase<Self> {
        EncoderBase::new(Self {
            base: Alphanum::new(),
            options:EncoderOptions::default(),
        })
    }

    fn saved_registers(&self) -> SmolSet<X86Register> {
        self.options.saved_registers.clone()
    }
}
