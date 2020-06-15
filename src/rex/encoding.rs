pub mod xor {
    pub mod byte {
        pub const KEYSIZE: usize = 1;
    }
    pub mod word {
        pub const KEYSIZE: usize = 2;
    }
    pub mod dword {
        pub const KEYSIZE: usize = 4;
    }
    pub mod qword {
        pub const KEYSIZE: usize = 8;
    }

    pub mod generic {
        use crate::rex::exceptions::ArgumentError;

        pub fn encode<'a>(
            keysize: usize,
            buf: &[u8],
            mut key: &'a [u8],
        ) -> Result<(Vec<u8>, &'a [u8]), ArgumentError> {
            let len = key.len();
            if len == 0 {
                return Err(ArgumentError("Zero key length".to_owned()));
            }

            if keysize != 0 && keysize != len {
                return Err(ArgumentError(format!(
                    "Key length {len}, expected {keysize}",
                    len = len,
                    keysize = keysize,
                )));
            }

            let mut encoded = vec![];

            for pos in 0..buf.len() {
                encoded.push(buf[pos] ^ key[pos % len]);
                key = _encode_mutate_key(buf, key, pos, len);
            }

            Ok((encoded, key))
        }

        /// kind of ghetto, but very convenient for mutating keys
        /// by default, do no key mutations
        fn _encode_mutate_key<'a>(buf: &[u8], key: &'a [u8], pos: usize, len: usize) -> &'a [u8] {
            let _ = (buf, pos, len);
            key
        }
    }
}
