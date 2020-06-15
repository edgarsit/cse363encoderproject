pub mod alpha2 {
    pub mod alpha_mixed {
        use crate::{logical::X86Register, smol_set::SmolSet};

        #[derive(Debug, Clone, thiserror::Error)]
        pub enum GenDecoderPrefixError {
            #[error("Critical: Offset is greater than 32")]
            Offset,
        }

        // Generates the decoder stub prefix
        //
        // @param [String] reg the register pointing to the encoded payload
        // @param [Fixnum] offset the offset to reach the encoded payload
        // @param [Array] modified_registers accounts the registers modified by the stub
        // @return [String] the alpha mixed decoder stub prefix
        fn gen_decoder_prefix(
            reg: X86Register,
            offset: usize,
            modified_registers: &mut SmolSet<X86Register>,
        ) -> Result<Vec<u8>, GenDecoderPrefixError> {
            if offset > 32 {
                return Err(GenDecoderPrefixError::Offset);
            }

            let mut mod_registers = SmolSet::new();
            let mut nop_regs = SmolSet::new();
            let mut mod_regs = SmolSet::new();
            let mut edx_regs = SmolSet::new();

            let mut r#mod;
            let edxmod;
            let nop;
            // use inc ebx as a nop here so we still pad correctly
            if offset <= 16 {
                nop = b"C".repeat(offset);
                if !nop.is_empty() {
                    nop_regs.push(X86Register::EBX);
                };

                r#mod = c![(b"I".repeat(16 - offset)) + nop + b"7QZ"]; // dec ecx,,, push ecx, pop edx;
                if offset != 16 {
                    mod_regs.push(X86Register::ECX);
                };
                mod_regs.extend(&nop_regs);
                mod_regs.push(X86Register::EDX);

                edxmod = b"J".repeat(17 - offset);
                if !edxmod.is_empty() {
                    edx_regs.push(X86Register::EDX);
                };
            } else {
                r#mod = b"A".repeat(offset - 16);
                if r#mod.is_empty() {
                    mod_regs.push(X86Register::ECX);
                }

                nop = b"C".repeat(16 - r#mod.len());
                if !nop.is_empty() {
                    nop_regs.push(X86Register::EBX);
                }

                r#mod = c![r#mod + nop + b"7QZ"];
                mod_regs.extend(&nop_regs);
                mod_regs.push(X86Register::EDX);

                edxmod = b"B".repeat(17 - (offset - 16));
                if !edxmod.is_empty() {
                    edx_regs.push(X86Register::EDX);
                }
            }

            if X86Register::EDX == reg {
                mod_registers.extend(edx_regs);
                mod_registers.extend(nop_regs);
                mod_registers.push(X86Register::ECX);
            } else {
                mod_registers.push(X86Register::ECX);
                mod_registers.extend(mod_regs);
            }

            modified_registers.extend(mod_registers);

            Ok(match reg {
                X86Register::EAX => c![b"PY" + r#mod], // push eax, pop ecx
                X86Register::ECX => c![b"I" + r#mod],  // dec ecx
                X86Register::EDX => c![edxmod + nop + b"7RY"], // dec edx,,, push edx, pop ecx
                X86Register::EBX => c![b"SY" + r#mod], // push ebx, pop ecx
                X86Register::ESP => c![b"TY" + r#mod], // push esp, pop ecx
                X86Register::EBP => c![b"UY" + r#mod], // push ebp, pop ecx
                X86Register::ESI => c![b"VY" + r#mod], // push esi, pop ecx
                X86Register::EDI => c![b"WY" + r#mod], // push edi, pop ecx
            })
        }

        // Generates the decoder stub
        //
        // @param [String] reg the register pointing to the encoded payload
        // @param [Fixnum] offset the offset to reach the encoded payload
        // @param [Array] modified_registers accounts the registers modified by the stub
        // @return [String] the alpha mixed decoder stub
        pub fn gen_decoder(
            reg: X86Register,
            offset: usize,
            modified_registers: &mut SmolSet<X86Register>,
        ) -> Result<Vec<u8>, GenDecoderPrefixError> {
            let mut mod_registers = SmolSet::new();

            let decoder = gen_decoder_prefix(reg, offset, &mut mod_registers)?;
            let decoder = c![
                decoder +
                b"jA" +          // push 0x41
                b"X" +           // pop eax
                b"P" +           // push eax
                b"0A0" +         // xor byte [ecx+30], al
                b"A" +           // inc ecx                        <---
                b"kAAQ" +        // imul eax, [ecx+42], 51 -> 10       |
                b"2AB" +         // xor al, [ecx + 42]                 |
                b"2BB" +         // xor al, [edx + 42]                 |
                b"0BB" +         // xor [edx + 42], al                 |
                b"A" +           // inc ecx                            |
                b"B" +           // inc edx                            |
                b"X" +           // pop eax                            |
                b"P" +           // push eax                           |
                b"8AB" +         // cmp [ecx + 42], al                 |
                b"uJ" +          // jnz short -------------------------
                b"I" +           // first encoded char, fixes the above J
            ];

            mod_registers.extend(&[
                X86Register::ESP,
                X86Register::EAX,
                X86Register::ECX,
                X86Register::EDX,
            ]);

            modified_registers.extend(mod_registers.into_iter());
            Ok(decoder)
        }

        pub fn add_terminator() -> Vec<u8> {
            b"AA".to_vec()
        }

        // inheritance?
        pub use super::generic::*;
    }
    pub mod generic {
        use crate::logical_arena::pop_random;
        use rand::Rng;

        // Note: 'A' is presumed to be accepted, but excluded from the accepted characters, because it serves as the terminator
        pub fn default_accepted_chars() -> Vec<u8> {
            (b'a'..=b'z')
                .chain(b'B'..=b'Z')
                .chain(b'0'..=b'9')
                .collect()
        }

        fn gen_second(block: u8, base: u8) -> u8 {
            // XOR encoder for ascii - unicode uses additive
            block ^ base
        }

        #[derive(Debug, Clone, thiserror::Error)]
        pub enum EncodeByteError {
            #[error("No encoding of 0x{block:2x} possible with limited character set")]
            RuntimeError { block: u8 },
        }

        pub fn encode_byte<R: Rng + ?Sized>(
            rng: &mut R,
            block: u8,
            badchars: &[u8],
        ) -> Result<Vec<u8>, EncodeByteError> {
            let mut accepted_chars = default_accepted_chars();
            accepted_chars.retain(|c| badchars.contains(c));

            let mut nibble_chars = vec![vec![]; 0x10];
            accepted_chars
                .iter()
                .for_each(|c| nibble_chars[usize::from(c & 0xF)].push(c));

            let mut poss_encodings = vec![];

            let block_low_nibble = block & 0x0F;
            let block_high_nibble = block >> 4;

            // Get list of chars suitable for expressing lower part of byte
            let first_chars = &nibble_chars[usize::from(block_low_nibble)];

            // Build a list of possible encodings
            first_chars.iter().for_each(|&&first_char| {
                let first_high_nibble = first_char >> 4;

                // # In the decoding process, the low nibble of the second char gets combined
                // # (either ADDed or XORed depending on the encoder) with the high nibble of the first char,
                // # and we want the high nibble of our input byte to result
                let second_low_nibble = gen_second(block_high_nibble, first_high_nibble) & 0x0F;

                // # Find valid second chars for this first char and add each combination to our possible encodings
                let second_chars = &nibble_chars[usize::from(second_low_nibble)];
                second_chars
                    .iter()
                    .for_each(|&&second_char| poss_encodings.push([second_char, first_char]));
            });

            // # Return a random encoding
            Ok(pop_random(rng, &mut poss_encodings)
                .ok_or(EncodeByteError::RuntimeError { block })?
                .to_vec())
        }
    }
}
