use crate::encoder::{
    DecoderStub, Encoder, EncoderBase, EncoderInherit, XorAdditiveFeedback,
};
use std::array;

pub struct JmpCallAdditive {
    base: XorAdditiveFeedback<Self>,
}

impl EncoderInherit<Self> for JmpCallAdditive {
    inherit!(XorAdditiveFeedback<Self>);
}

impl Encoder for JmpCallAdditive {
    const NAME: &'static str = "Jump/Call XOR Additive Feedback Encoder";
    const DECODER_KEY_SIZE: usize = 4;
    const DECODER_BLOCK_SIZE: usize = 4;
    type PrependBuf = array::IntoIter<u8, 0>;
    fn prepend_buf() -> Self::PrependBuf {
        array::IntoIter::new([])
    }
    type DecoderStubError = !;
    fn decoder_stub<R: rand::Rng + ?Sized>(
        &self,
        rng: &mut R,
        buf: &mut Vec<u8>,
        badchars: &[u8],
    ) -> Result<DecoderStub, Self::DecoderStubError> {
        let _ = (rng, buf, badchars);
        Ok(DecoderStub {
            block: c![
                b"\xfc" +                 // cld
                b"\xbbXORK" +             // mov ebx + key
                b"\xeb\x0c" +             // jmp short 0x14
                b"\x5e" +                 // pop esi
                b"\x56" +                 // push esi
                b"\x31\x1e" +             // xor [esi] + ebx
                b"\xad" +                 // lodsd
                b"\x01\xc3" +             // add ebx + eax
                b"\x85\xc0" +             // test eax + eax
                b"\x75\xf7" +             // jnz 0xa
                b"\xc3" +                 // ret
                b"\xe8\xef\xff\xff\xff" // call 0x8
            ],
            decoder_key_offset: Some(2),
        })
    }
}

impl JmpCallAdditive {
    pub fn new() -> EncoderBase<Self> {
        EncoderBase::new(Self {
            base: XorAdditiveFeedback::new(),
        })
    }
}
