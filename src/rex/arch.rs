pub mod x86 {
    use crate::{logical::X86Register, rex::badchar_index, smol_set::SmolSet};
    use lazy_static::lazy_static;
    use rand::{prelude::SliceRandom, Rng};

    /// This method returns an array of 'safe' FPU instructions

    pub fn fpu_instructions() -> &'static [[u8; 2]] {
        lazy_static! {
            static ref FPUS: Vec<[u8; 2]> = {
                let len: usize = [
                    (0xe8_u8..=0xee),
                    (0xc0..=0xcf),
                    (0xc0..=0xdf),
                    (0xc0..=0xdf),
                    (0xc0..=0xc7),
                ]
                .into_iter()
                .map(|x| x.len())
                .sum();

                let mut fpus = Vec::with_capacity(len + 5);

                // FLD1/FLDL2T/FLDL2E/FLDPI/FLDLG2/FLDLN2/FLDZ
                (0xe8..=0xee).for_each(|x| fpus.push([b'\xd9', x]));
                // FLD
                (0xc0..=0xcf).for_each(|x| fpus.push([b'\xd9', x]));
                // FCMOV
                (0xc0..=0xdf).for_each(|x| fpus.push([b'\xda', x]));
                // FCMOV
                (0xc0..=0xdf).for_each(|x| fpus.push([b'\xdb', x]));
                // FFREE
                (0xc0..=0xc7).for_each(|x| fpus.push([b'\xdd', x]));

                // FNOP
                fpus.push(*b"\xd9\xd0");
                // FABS
                fpus.push(*b"\xd9\xe1");
                // FDECSTP
                fpus.push(*b"\xd9\xf6");
                // FINCSTP
                fpus.push(*b"\xd9\xf7");
                // FXAM
                fpus.push(*b"\xd9\xe5");

                // # This FPU instruction seems to fail consistently on Linux
                // # fpus << "\xdb\xe1"

                fpus
            };
        }
        &FPUS
    }

    /// This method returns an array containing a geteip stub, a register, and an offset
    /// This method will return nil if the getip generation fails

    pub fn geteip_fpu<R: Rng + ?Sized>(
        rng: &mut R,
        badchars: &[u8],
        modified_registers: &mut SmolSet<X86Register>,
    ) -> Option<(Vec<u8>, X86Register, usize)> {
        // Bail out early if D9 is restricted
        if badchars.contains(&b'\xd9') {
            return None;
        }

        // Create a list of FPU instructions
        let fpus: Vec<_> = fpu_instructions()
            .iter()
            .filter(|&str| badchar_index(str, badchars).is_none())
            .collect();

        if fpus.is_empty() {
            return None;
        }

        // Create a list of registers to use for fnstenv
        let mut dsts: SmolSet<_> = X86Register::REGNUM_SET
            .into_iter()
            .copied()
            .filter(|&c| !badchars.contains(&(0x70 + c.reg_number())))
            .collect();

        if dsts.contains(&X86Register::ESP) && badchars.contains(&b'\x24') {
            dsts.remove_item(X86Register::ESP);
        }

        if dsts.is_empty() {
            return None;
        }

        // Grab a random FPU instruction
        let fpu = fpus.choose(rng).unwrap();

        // Grab a random register from dst
        while let Some(dst) = dsts.pop_random(rng) {
            let mut buf = vec![];
            let mut mod_registers: SmolSet<_> = [X86Register::ESP].into_iter().copied().collect();

            // If the register is not ESP, copy ESP
            if dst != X86Register::ESP {
                if badchars.contains(&(0x70 + dst.reg_number())) {
                    continue;
                }
                if !(badchars.contains(&b'\x89') || badchars.contains(&(0xE0 + dst.reg_number()))) {
                    buf.extend_from_slice(&[b'\x89', (0xe0 + dst.reg_number())]);
                } else {
                    if badchars.contains(&b'\x54') {
                        continue;
                    }
                    if badchars.contains(&(0x58 + dst.reg_number())) {
                        continue;
                    }
                    buf.extend_from_slice(&[b'\x54', (0x58 + dst.reg_number())]);
                }
                mod_registers.push(dst);
            }

            let mut pad = 0;
            // while pad < (128 - 12) && badchars.contains(&(256 - 12 - pad)) {
            while pad < (128 - 12) && badchars.contains(&(0_u8.wrapping_sub(12).wrapping_sub(pad)))
            {
                pad += 4
            }

            // Give up on finding a value to use here
            if pad == (128 - 12) {
                return None;
            }

            let buf_len = buf.len();
            // FNSTENV
            let mut out = c!(buf + fpu + b"\xd9" + (0x70 + dst.reg_number()));
            if dst == X86Register::ESP {
                out.push(b'\x24');
            }
            out.push(0_u8.wrapping_sub(12).wrapping_sub(pad));
            let mut regs = X86Register::REGNUM_SET.to_vec();
            regs.shuffle(rng);
            for reg in regs {
                if reg == X86Register::ESP {
                    continue;
                }
                if badchars.contains(&(0x58 + reg.reg_number())) {
                    continue;
                }
                mod_registers.push(reg);

                // Pop the value back out
                (0..pad / 4).for_each(|_| out.push(0x58 + reg.reg_number()));

                // Fix the value to point to self
                let gap = out.len() - buf_len;

                modified_registers.extend(mod_registers);

                return Some((out, reg, gap));
            }
            mod_registers.remove_item(dst);
        }
        None
    }
}
