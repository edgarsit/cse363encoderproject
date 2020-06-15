use crate::{
    logical::X86Register,
    rex::{self, badchar_index},
    smol_set::SmolSet,
};
use rand::{seq::SliceRandom, Rng, RngCore};
use std::{array, collections::HashSet, convert::TryFrom, error::Error, fmt, marker::PhantomData};

// add comments

pub struct EncoderState {
    pub encoded: Vec<u8>,
}

impl EncoderState {
    fn new(encoded: Vec<u8>) -> Self {
        Self { encoded }
    }
}

#[derive(Debug, Clone)]
pub struct EncoderBase<T> {
    encoder: T,
}

impl<T: Encoder + EncoderInherit<T>> EncoderBase<T> {
    pub fn new(encoder: T) -> Self {
        Self { encoder }
    }

    pub fn into_dyn(self) -> EncoderBase<Box<dyn DynEncoder>>
    where
        T::FindKeyError: Error + 'static,
        T::DecoderStubError: 'static,
        T: 'static,
    {
        let encoder: Box<dyn DynEncoder> = Box::new(self.encoder);
        EncoderBase { encoder }
    }

    /// This method generates an encoded version of the supplied buffer in buf
    /// using the bad characters as guides.  On success, an encoded and
    /// functional version of the supplied buffer will be returned.  Otherwise,
    /// an exception will be thrown if an error is encountered during the
    /// encoding process.
    pub fn encode<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        mut buf: Vec<u8>,
        badchars: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>>
    where
        T::FindKeyError: Error + 'static,
        T::DecoderStubError: 'static,
    {
        let mut state = EncoderState::new(Vec::new());

        // Prepend data to the buffer as necessary
        drop(buf.splice(..0, T::prepend_buf()));

        // If this encoder is key-based and we don't already have a key, find one
        let decoder_stub = self.encoder.decoder_stub(rng, &mut buf, badchars)?;
        let key = if T::DECODER_KEY_SIZE != 0 {
            // Find a key that doesn't contain and wont generate any bad
            // characters
            Self::obtain_key(&self.encoder, rng, &buf, badchars, &decoder_stub).map_err(|e| {
                Box::<dyn Error>::from(format!(
                    "A key could not be found for the {} encoder: {}",
                    T::NAME,
                    e,
                ))
            })?
        } else {
            0
        };

        // # Call encode_begin to do any encoder specific pre-processing
        T::encode_begin(&mut state)?;

        // # Perform the actual encoding operation with the determined state
        let encoded = Self::do_encode(rng, &self.encoder, &buf, badchars, key, &decoder_stub)
            .map_err(|e| {
                Box::<dyn Error>::from(format!("An error occurred while encoding: {:?}", e,))
            })?;

        let mut state = EncoderState::new(encoded);
        // # Call encoded_end to do any encoder specific post-processing
        T::encode_end(&mut state)?;

        // # Return the encoded buffer to the caller
        Ok(state.encoded)
    }

    /// Obtains the key to use during encoding.  If context encoding is enabled,
    /// special steps are taken.  Otherwise, the derived class is given an
    /// opportunity to find the key.
    fn obtain_key<R: Rng + ?Sized>(
        encoder: &T,
        rng: &mut R,
        buf: &[u8],
        badchars: &[u8],
        decoder_stub: &DecoderStub,
    ) -> Result<u32, Box<dyn Error>>
    where
        T::FindKeyError: Error + 'static,
    {
        // if datastore['EnableContextEncoding']
        //   return find_context_key(buf, badchars, state)
        // else
        T::find_key(encoder, rng, buf, badchars, decoder_stub).map_err(From::from)
    }

    /// Performs the actual encoding operation after the encoder state has been
    /// initialized and is ready to go.
    fn do_encode<R: Rng + ?Sized>(
        rng: &mut R,
        encoder: &T,
        buf: &[u8],
        badchars: &[u8],
        mut key: u32,
        stub: &DecoderStub,
    ) -> Result<Vec<u8>, BadCharError> {
        // # Copy the decoder stub since we may need to modify it
        let mut stub = stub.clone();
        if let Some(decoder_key_offset) = stub.decoder_key_offset {
            // # Substitute the decoder key in the copy of the decoder stub with the
            // # one that we found
            let real_key = key;

            // # If we're using context encoding, the actual value we use for
            // # substitution is the context address, not the key we use for
            // # encoding
            // real_key = state.context_address if (state.context_encoding)

            let range = decoder_key_offset..(decoder_key_offset + T::DECODER_KEY_SIZE);
            drop(
                stub.block
                    .splice(range, array::IntoIter::new(real_key.to_le_bytes())),
            );
        } else {
            stub.block = T::encode_finalize_stub(&mut EncoderState::new(Vec::new()), stub.block);
        }
        let stub = stub.block;

        let mut encoded = Vec::new();

        // # Walk the buffer encoding each block along the way
        if T::DECODER_BLOCK_SIZE != 0 {
            let mut buf = buf.to_vec();
            let remainder = T::DECODER_BLOCK_SIZE - (buf.len() % T::DECODER_BLOCK_SIZE);
            buf.extend((0..remainder).map(|_| b'\x00'));
            debug_assert_eq!(buf.len() % T::DECODER_BLOCK_SIZE, 0);
            let iter = buf.chunks_exact(T::DECODER_BLOCK_SIZE);
            debug_assert!(iter.remainder().is_empty());

            for block in iter {
                let tmp = T::encode_block(encoder, rng, &mut key, block, badchars);
                debug_assert!(tmp.len() == T::DECODER_BLOCK_SIZE);
                encoded.extend_from_slice(&tmp);
            }
        } else {
            encoded = T::encode_block(encoder, rng, &mut key, &stub, badchars);
        }

        let stub_size = stub.len();
        // # Prefix the decoder stub to the encoded buffer
        drop(encoded.splice(..0, stub));

        // # Last but not least, do one last badchar pass to see if the stub +
        // # encoded payload leads to any bad char issues...
        if let Some(badchar_idx) = badchar_index(&encoded, badchars) {
            return Err(BadCharError {
                index: badchar_idx,
                stub_size,
            });
        }

        Ok(encoded)
    }
}

impl EncoderBase<Box<dyn DynEncoder>> {
    /// This method generates an encoded version of the supplied buffer in buf
    /// using the bad characters as guides.  On success, an encoded and
    /// functional version of the supplied buffer will be returned.  Otherwise,
    /// an exception will be thrown if an error is encountered during the
    /// encoding process.
    pub fn encode(
        &self,
        rng: &mut dyn RngCore,
        mut buf: Vec<u8>,
        badchars: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut state = EncoderState::new(Vec::new());

        // Prepend data to the buffer as necessary
        self.encoder.prepend_buf(&mut buf);

        // If this encoder is key-based and we don't already have a key, find one
        let decoder_stub = self.encoder.decoder_stub(rng, &mut buf, badchars)?;
        let key = if self.encoder.decoder_key_size() != 0 {
            // Find a key that doesn't contain and wont generate any bad
            // characters
            self.dyn_obtain_key(rng, &buf, badchars, &decoder_stub)
                .map_err(|e| {
                    Box::<dyn Error>::from(format!(
                        "A key could not be found for the {} encoder: {}",
                        self.encoder.name(),
                        e,
                    ))
                })?
        } else {
            0
        };

        // # Call encode_begin to do any encoder specific pre-processing
        self.encoder.encode_begin(&mut state)?;

        // # Perform the actual encoding operation with the determined state
        let encoded = <EncoderBase<Box<dyn DynEncoder>>>::do_encode(
            self,
            rng,
            &buf,
            badchars,
            key,
            &decoder_stub,
        )
        .map_err(|e| {
            Box::<dyn Error>::from(format!("An error occurred while encoding: {:?}", e,))
        })?;

        let mut state = EncoderState::new(encoded);
        // # Call encoded_end to do any encoder specific post-processing
        self.encoder.encode_end(&mut state)?;

        // # Return the encoded buffer to the caller
        Ok(state.encoded)
    }

    /// Obtains the key to use during encoding.  If context encoding is enabled,
    /// special steps are taken.  Otherwise, the derived class is given an
    /// opportunity to find the key.
    fn dyn_obtain_key(
        &self,
        rng: &mut dyn RngCore,
        buf: &[u8],
        badchars: &[u8],
        decoder_stub: &DecoderStub,
    ) -> Result<u32, Box<dyn Error>> {
        // if datastore['EnableContextEncoding']
        //   return find_context_key(buf, badchars, state)
        // else
        self.encoder
            .find_key(rng, buf, badchars, decoder_stub)
            .map_err(From::from)
    }

    /// Performs the actual encoding operation after the encoder state has been
    /// initialized and is ready to go.
    fn do_encode(
        &self,
        rng: &mut dyn RngCore,
        buf: &[u8],
        badchars: &[u8],
        mut key: u32,
        stub: &DecoderStub,
    ) -> Result<Vec<u8>, BadCharError> {
        let encoder = &self.encoder;
        // # Copy the decoder stub since we may need to modify it
        let mut stub = stub.clone();
        if let Some(decoder_key_offset) = stub.decoder_key_offset {
            // # Substitute the decoder key in the copy of the decoder stub with the
            // # one that we found
            let real_key = key;

            // # If we're using context encoding, the actual value we use for
            // # substitution is the context address, not the key we use for
            // # encoding
            // real_key = state.context_address if (state.context_encoding)

            let range = decoder_key_offset..(decoder_key_offset + encoder.decoder_key_size());
            drop(
                stub.block
                    .splice(range, array::IntoIter::new(real_key.to_le_bytes())),
            );
        } else {
            stub.block =
                encoder.encode_finalize_stub(&mut EncoderState::new(Vec::new()), stub.block);
        }
        let stub = stub.block;

        let mut encoded = Vec::new();

        // # Walk the buffer encoding each block along the way
        if encoder.decoder_block_size() != 0 {
            let mut buf = buf.to_vec();
            let remainder =
                encoder.decoder_block_size() - (buf.len() % encoder.decoder_block_size());
            buf.extend((0..remainder).map(|_| b'\x00'));
            debug_assert_eq!(buf.len() % encoder.decoder_block_size(), 0);
            let iter = buf.chunks_exact(encoder.decoder_block_size());
            debug_assert!(iter.remainder().is_empty());

            for block in iter {
                let tmp = encoder.encode_block(rng, &mut key, block, badchars);
                debug_assert!(tmp.len() == encoder.decoder_block_size());
                encoded.extend_from_slice(&tmp);
            }
        } else {
            encoded = encoder.encode_block(rng, &mut key, &stub, badchars);
        }

        let stub_size = stub.len();
        // # Prefix the decoder stub to the encoded buffer
        drop(encoded.splice(..0, stub));

        // # Last but not least, do one last badchar pass to see if the stub +
        // # encoded payload leads to any bad char issues...
        if let Some(badchar_idx) = badchar_index(&encoded, badchars) {
            return Err(BadCharError {
                index: badchar_idx,
                stub_size,
            });
        }

        Ok(encoded)
    }
}

fn key_bytes_to_integer(key_bytes: &[u8]) -> u32 {
    let tmp = key_bytes.get(0..4).map(TryFrom::try_from).unwrap().unwrap();
    u32::from_le_bytes(tmp)
}

fn integer_to_key_bytes(integer: u32) -> [u8; 4] {
    integer.to_le_bytes()
}

#[derive(Debug)]
pub struct EncoderInheritBase<T>(PhantomData<T>);

impl<T> EncoderInheritBase<T> {
    const fn new() -> Self {
        Self(PhantomData)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("Could not find key")]
pub struct EncoderInheritBaseFindKeyError;

impl<T: Encoder + EncoderInherit<T>> EncoderInherit<T> for EncoderInheritBase<T> {
    type FindKeyError = EncoderInheritBaseFindKeyError;

    ///  This method finds a compatible key for the supplied buffer based also on
    ///  the supplied bad characters list.  This is meant to make encoders more
    ///  reliable and less prone to bad character failure by doing a fairly
    ///  complete key search before giving up on an encoder.
    fn find_key<R: Rng + ?Sized>(
        encoder: &T,
        rng: &mut R,
        buf: &[u8],
        badchars: &[u8],
        decoder_stub: &DecoderStub,
    ) -> Result<u32, Self::FindKeyError> {
        let _ = (encoder, decoder_stub);

        // # Otherwise, we use the traditional method
        let mut key_bytes = vec![];
        let bad_keys = T::find_bad_keys(buf, badchars);
        assert!(bad_keys.len() == T::DECODER_KEY_SIZE);
        let mut found = false;
        let allset = 0..=u8::MAX;

        // # Keep chugging until we find something...right
        while !found {
            // # Scan each byte position
            let t: Result<Vec<u8>, EncoderInheritBaseFindKeyError> = bad_keys
                .iter()
                .map(|bad_key| {
                    // # Subtract the bad and leave the good
                    let good_keys: Vec<_> =
                        allset.clone().filter(|b| !bad_key.contains(b)).collect();

                    Ok(*good_keys
                        .choose(rng)
                        .ok_or(EncoderInheritBaseFindKeyError)?)
                })
                .collect();
            key_bytes = t?;

            // # Assume that we're going to rock this...
            found = true;

            // # Scan each byte and see what we've got going on to make sure
            // # no funny business is happening
            for byte in &key_bytes {
                if badchars.contains(byte) {
                    found = false;
                    continue;
                }
            }

            if found {
                found = T::find_key_verify(buf, &key_bytes, badchars)
            }
        }

        // # Do we have all the key bytes accounted for?
        assert_eq!(key_bytes.len(), T::DECODER_KEY_SIZE);

        Ok(key_bytes_to_integer(&key_bytes))
    }
    /// Returns the list of bad keys associated with this encoder.
    fn find_bad_keys(buf: &[u8], badchars: &[u8]) -> Vec<HashSet<u8>> {
        let _ = (buf, badchars);
        vec![HashSet::new(); T::DECODER_KEY_SIZE]
    }
    /// Called once for each block being encoded based on the attributes of the
    /// decoder.
    fn encode_block<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        key: &mut u32,
        block: &[u8],
        badchars: &[u8],
    ) -> Vec<u8> {
        let _ = (rng, key, badchars);
        block.to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct DecoderStub {
    pub block: Vec<u8>,
    pub decoder_key_offset: Option<usize>,
}

pub trait EncoderInherit<T: Encoder + ?Sized> {
    type FindKeyError;

    fn find_key<R: Rng + ?Sized>(
        encoder: &T,
        rng: &mut R,
        buf: &[u8],
        badchars: &[u8],
        decoder_stub: &DecoderStub,
    ) -> Result<u32, Self::FindKeyError>;
    /// output should have length `T::DECODER_KEY_SIZE`
    fn find_bad_keys(buf: &[u8], badchars: &[u8]) -> Vec<HashSet<u8>>;
    fn find_key_verify(buf: &[u8], key_bytes: &[u8], badchars: &[u8]) -> bool {
        let _ = (buf, key_bytes, badchars);
        true
    }
    /// should have length `T::DECODER_BLOCK_SIZE`
    fn encode_block<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        key: &mut u32,
        block: &[u8],
        badchars: &[u8],
    ) -> Vec<u8>;
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("Encoding failed due to a bad character (index={index}")]
pub struct BadCharError {
    index: usize,
    stub_size: usize,
}

pub trait Encoder {
    const NAME: &'static str;

    const DECODER_KEY_SIZE: usize;
    const DECODER_BLOCK_SIZE: usize;

    type PrependBuf: IntoIterator<Item = u8>;
    fn prepend_buf() -> Self::PrependBuf;

    type DecoderStubError: Error;
    fn decoder_stub<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        buf: &mut Vec<u8>,
        badchars: &[u8],
    ) -> Result<DecoderStub, Self::DecoderStubError>;

    fn encode_begin(state: &mut EncoderState) -> Result<(), Box<dyn Error>> {
        let _ = state;
        Ok(())
    }
    fn encode_end(state: &mut EncoderState) -> Result<(), Box<dyn Error>> {
        let _ = state;
        Ok(())
    }

    // NB: only uses of `encode_finalize_stub` are
    // https://github.com/rapid7/metasploit-framework/blob/76954957c740525cff2db5a60bcf936b4ee06c42/modules/encoders/ppc/longxor_tag.rb
    //      state.key
    // https://github.com/rapid7/metasploit-framework/blob/76954957c740525cff2db5a60bcf936b4ee06c42/modules/encoders/ppc/longxor.rb
    //      state.key and state.buf
    // https://github.com/rapid7/metasploit-framework/blob/59573151675cc21ce020e7284ecd6f4532ae6eef/modules/encoders/mipsbe/byte_xori.rb
    //      state.key, state.decoder_key_size, state.decoder_key_pack
    // https://github.com/rapid7/metasploit-framework/blob/59573151675cc21ce020e7284ecd6f4532ae6eef/modules/encoders/mipsle/byte_xori.rb
    //      state.key, state.decoder_key_size, state.decoder_key_pack

    /// This callback allows a derived class to finalize a stub after a key have
    /// been selected.  The finalized stub should be returned.
    fn encode_finalize_stub(state: &mut EncoderState, stub: Vec<u8>) -> Vec<u8> {
        let _ = state;
        stub
    }
}

pub trait DynEncoder {
    fn name(&self) -> &'static str;
    fn decoder_key_size(&self) -> usize;
    fn decoder_block_size(&self) -> usize;
    fn prepend_buf(&self, buf: &mut Vec<u8>);
    fn decoder_stub(
        &self,
        rng: &mut dyn RngCore,
        buf: &mut Vec<u8>,
        badchars: &[u8],
    ) -> Result<DecoderStub, Box<dyn Error>>;
    fn encode_begin(&self, state: &mut EncoderState) -> Result<(), Box<dyn Error>>;
    fn encode_end(&self, state: &mut EncoderState) -> Result<(), Box<dyn Error>>;
    fn encode_finalize_stub(&self, state: &mut EncoderState, stub: Vec<u8>) -> Vec<u8>;

    fn find_key(
        &self,
        rng: &mut dyn RngCore,
        buf: &[u8],
        badchars: &[u8],
        decoder_stub: &DecoderStub,
    ) -> Result<u32, Box<dyn Error>>;
    fn encode_block(
        &self,
        rng: &mut dyn RngCore,
        key: &mut u32,
        block: &[u8],
        badchars: &[u8],
    ) -> Vec<u8>;
}

impl<T> DynEncoder for T
where
    T: Encoder + EncoderInherit<T>,
    T::DecoderStubError: 'static,
    T::FindKeyError: Error + 'static,
{
    fn name(&self) -> &'static str {
        T::NAME
    }
    fn decoder_key_size(&self) -> usize {
        T::DECODER_KEY_SIZE
    }
    fn decoder_block_size(&self) -> usize {
        T::DECODER_BLOCK_SIZE
    }
    fn prepend_buf(&self, buf: &mut Vec<u8>) {
        drop(buf.splice(..0, <T as Encoder>::prepend_buf()))
    }
    fn decoder_stub(
        &self,
        rng: &mut dyn RngCore,
        buf: &mut Vec<u8>,
        badchars: &[u8],
    ) -> Result<DecoderStub, Box<dyn Error>> {
        <T as Encoder>::decoder_stub(self, rng, buf, badchars).map_err(From::from)
    }
    fn encode_begin(&self, state: &mut EncoderState) -> Result<(), Box<dyn Error>> {
        T::encode_begin(state)
    }
    fn encode_end(&self, state: &mut EncoderState) -> Result<(), Box<dyn Error>> {
        T::encode_end(state)
    }
    fn encode_finalize_stub(&self, state: &mut EncoderState, stub: Vec<u8>) -> Vec<u8> {
        T::encode_finalize_stub(state, stub)
    }

    fn find_key(
        &self,
        rng: &mut dyn RngCore,
        buf: &[u8],
        badchars: &[u8],
        decoder_stub: &DecoderStub,
    ) -> Result<u32, Box<dyn Error>> {
        T::find_key(self, rng, buf, badchars, decoder_stub).map_err(From::from)
    }
    fn encode_block(
        &self,
        rng: &mut dyn RngCore,
        key: &mut u32,
        block: &[u8],
        badchars: &[u8],
    ) -> Vec<u8> {
        self.encode_block(rng, key, block, badchars)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn s() {
        let e = crate::shikata_ga_nai::ShikataGaNai::new();
        let e = e.into_dyn();
        t(e);
        let e = crate::shikata_ga_nai::ShikataGaNai::new();
        let e = e.into_dyn();
        r(e);
    }
    fn t(_: EncoderBase<Box<dyn DynEncoder>>) {}
    fn r(_: EncoderBase<Box<impl DynEncoder + ?Sized>>) {}
}
#[derive(Debug)]
pub struct Xor<T> {
    base: EncoderInheritBase<T>,
}

impl<T> Xor<T> {
    const fn new() -> Self {
        Self {
            base: EncoderInheritBase::new(),
        }
    }
}

impl<T: Encoder + EncoderInherit<T>> EncoderInherit<T> for Xor<T> {
    inherit!(@find_key EncoderInheritBase<T>);
    fn find_bad_keys(buf: &[u8], badchars: &[u8]) -> Vec<HashSet<u8>> {
        if badchars.is_empty() {
            return EncoderInheritBase::<T>::find_bad_keys(buf, badchars);
        }

        let mut bad_keys = vec![HashSet::new(); T::DECODER_KEY_SIZE];

        // # Scan through all the badchars and build out the bad_keys array
        // # based on the XOR'd combinations that can occur at certain bytes
        // # to produce bad characters
        buf.iter().enumerate().for_each(|(byte_idx, byte)| {
            badchars.iter().for_each(|badchar| {
                let _ = bad_keys[byte_idx % T::DECODER_KEY_SIZE].insert(byte ^ badchar);
            });
        });

        badchars.iter().for_each(|&badchar| {
            bad_keys.iter_mut().for_each(|bad_key| {
                let _ = bad_key.insert(badchar);
            });
        });

        bad_keys
    }
    fn encode_block<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        key: &mut u32,
        block: &[u8],
        badchars: &[u8],
    ) -> Vec<u8> {
        let _ = (rng, badchars);
        let keysize = match T::DECODER_KEY_SIZE {
            t @ rex::encoding::xor::qword::KEYSIZE
            | t @ rex::encoding::xor::dword::KEYSIZE
            | t @ rex::encoding::xor::word::KEYSIZE
            | t @ rex::encoding::xor::byte::KEYSIZE => t,
            _ => rex::encoding::xor::dword::KEYSIZE,
        };
        rex::encoding::xor::generic::encode(keysize, block, &key.to_le_bytes())
            .unwrap()
            .0
    }
}

pub enum XorAdditiveFeedbackFindKeyError<T> {
    UnableToFindKey,
    DecoderStubContainsABadCharacter,
    EncoderFailedToEncodeWithoutBadCharacters,
    __Unused(PhantomData<T>),
}

impl<T> fmt::Debug for XorAdditiveFeedbackFindKeyError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use XorAdditiveFeedbackFindKeyError::*;
        match self {
            UnableToFindKey => write!(f, "UnableToFindKey"),
            DecoderStubContainsABadCharacter => write!(f, "DecoderStubContainsABadCharacter,"),
            EncoderFailedToEncodeWithoutBadCharacters => {
                write!(f, "EncoderFailedToEncodeWithoutBadCharacters,")
            }
            __Unused(_) => write!(f, "__Unused(PhantomData<T>),"),
        }
    }
}

impl<T> fmt::Display for XorAdditiveFeedbackFindKeyError<T>
where
    T: Encoder,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use XorAdditiveFeedbackFindKeyError::*;
        match self {
            UnableToFindKey => write!(f, "Unable to find key"),
            DecoderStubContainsABadCharacter => {
                write!(f, "The {} decoder stub contains a bad character", T::NAME)
            }
            EncoderFailedToEncodeWithoutBadCharacters => write!(
                f,
                "The {} encoder failed to encode without bad characters.",
                T::NAME
            ),
            __Unused(_) => unreachable!(),
        }
    }
}

impl<T> Error for XorAdditiveFeedbackFindKeyError<T> where T: Encoder {}

#[derive(Debug)]
pub struct XorAdditiveFeedback<T> {
    base: Xor<T>,
}

impl<T> XorAdditiveFeedback<T> {
    pub fn new() -> Self {
        Self { base: Xor::new() }
    }
}

impl<T: Encoder + EncoderInherit<T>> EncoderInherit<T> for XorAdditiveFeedback<T> {
    inherit!(@find_bad_keys Xor<T>);

    type FindKeyError = XorAdditiveFeedbackFindKeyError<T>;
    fn find_key<R: Rng + ?Sized>(
        encoder: &T,
        rng: &mut R,
        buf: &[u8],
        badchars: &[u8],
        decoder_stub: &DecoderStub,
    ) -> Result<u32, Self::FindKeyError> {
        let mut key = <Xor<T>>::find_key(encoder, rng, buf, badchars, decoder_stub)
            .map_err(|_| XorAdditiveFeedbackFindKeyError::<T>::UnableToFindKey)?;
        let mut key_bytes = integer_to_key_bytes(key);

        let mut valid = false;
        // # Save the original key_bytes so we can tell if we loop around
        let orig_key_bytes = key_bytes;

        // # While we haven't found a valid key, keep trying the encode operation
        while !valid {
            // # Initialize the state back to defaults since we're trying to find a
            // # key.
            // Encoder::init_state(state);
            //  does the following:
            // # Update the state with default decoder information
            // state.decoder_key_offset = Self::decoder_key_offset();
            // state.decoder_key_size = Self::decoder_key_size();
            // state.decoder_stub = None;

            // // # Restore the original buffer in case it was modified.
            // state.buf = state.orig_buf.clone();

            key = key_bytes_to_integer(&key_bytes);
            let tmp = || -> Result<(), BadCharError> {
                // state.key = Some(key);
                // state.orig_key = Some(key);
                // state.encoded.clear();

                // # If the key itself contains a bad character, throw the bad
                // # character exception with the index of the bad character in the
                // # key.  Use a stub_size of zero to bypass the check to in the
                // # rescue block.
                if let Some(idx) = badchar_index(&key.to_le_bytes(), badchars) {
                    return Err(BadCharError {
                        index: idx,
                        stub_size: 0,
                    });
                }
                // NB: we only care if it succeeds or not
                let _ =
                    EncoderBase::<T>::do_encode(rng, encoder, buf, badchars, key, decoder_stub)?;
                valid = true;
                Ok(())
            }();
            if let Err(info) = tmp {
                if info.index < info.stub_size {
                    return Err(
                        XorAdditiveFeedbackFindKeyError::<T>::DecoderStubContainsABadCharacter,
                    );
                }
                // # Determine the actual index to the bad character inside the
                // # encoded payload by removing the decoder stub from the index and
                // # modulus off the decoder's key size
                let idx = (info.index - info.stub_size) % T::DECODER_KEY_SIZE;

                // # Increment the key byte at the index that the bad character was
                // # detected
                key_bytes[idx] = key_bytes[idx].wrapping_add(1);

                if key_bytes[idx] == orig_key_bytes[idx] {
                    return Err(
                        XorAdditiveFeedbackFindKeyError::EncoderFailedToEncodeWithoutBadCharacters,
                    );
                }
            }
        }

        Ok(key)
    }
    fn encode_block<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        key: &mut u32,
        block: &[u8],
        badchars: &[u8],
    ) -> Vec<u8> {
        let _ = (rng, badchars);
        assert!(block.len() == T::DECODER_BLOCK_SIZE);
        assert!(T::DECODER_BLOCK_SIZE == T::DECODER_KEY_SIZE);
        // # XOR the key with the current block
        let tmp = block.get(0..4).map(TryFrom::try_from).unwrap().unwrap();
        let orig = u32::from_le_bytes(tmp);
        let oblock = orig ^ *key;

        // # Add the original block contents to the key
        let (rem, ofl) = 1_u32.overflowing_shl(T::DECODER_KEY_SIZE as u32 * 8);

        let new_key = key.wrapping_add(orig);
        *key = if ofl { new_key } else { new_key % rem };

        // # Return the XOR'd block
        oblock.to_le_bytes().to_vec()
    }
}

#[derive(Debug)]
pub struct Alphanum<T: Encoder> {
    /// The register that points to the encoded payload
    pub buffer_register: Option<X86Register>,
    /// The offset to the buffer from the start of the register
    pub buffer_offset: Option<usize>,
    /// Use SEH to determine the address of the stub (Windows only)
    pub allow_win32_seh: bool,

    base: EncoderInheritBase<T>,
}

impl<T: Encoder> Alphanum<T> {
    pub fn new() -> Self {
        Self {
            buffer_register: None,
            buffer_offset: Some(0),
            allow_win32_seh: false,
            base: EncoderInheritBase(PhantomData),
        }
    }
}

impl<T: Encoder + EncoderInherit<T>> EncoderInherit<T> for Alphanum<T> {
    inherit!(EncoderInheritBase<T>);
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("A valid opcode permutation could not be found.")]
pub struct BadGenerateError;

#[derive(Debug, Clone, Default)]
pub struct EncoderOptions {
    pub saved_registers: SmolSet<X86Register>,
    pub buffer_offset: Option<u32>,
}
