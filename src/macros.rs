use crate::logical_arena::{LogicalBlockRefOrEndBlock, LogicalRegister};
use std::ops;

pub struct Stub;

impl ops::Sub for Stub {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let _ = (self, rhs);
        Self
    }
}

impl ops::Sub<usize> for Stub {
    type Output = usize;
    fn sub(self, rhs: usize) -> Self::Output {
        let _ = (self, rhs);
        usize::MAX
    }
}

#[derive(Debug)]
pub struct LiveLogicalBlockStub;

impl LiveLogicalBlockStub {
    pub fn regnum_of(&self, _: LogicalRegister) -> Result<u8, !> {
        let _ = self;
        Ok(0)
    }

    pub fn offset_of(&self, _: impl LogicalBlockRefOrEndBlock) -> Stub {
        let _ = self;
        Stub
    }
}

macro_rules! p {
    () => {
        PermInner::S(&[])
    };
    ($lb:ident | $name:expr, $($x:expr),+ $(,)?) => {
        {
            let $lb = $crate::macros::LiveLogicalBlockStub;
            let len = p!(@sum $($x),+);
            PermInner::from_fn(len, move |$lb, buf| {
                $($x.write(buf, $lb)?;)+
                Ok(())
            }, $name)
        }
    };
    (_ | $name:expr, $($x:expr),+ $(,)?) => {
        p!(_lb | Some($name), $($x),+)
    };
    ($lb:ident, $($x:expr),+ $(,)?) => {
        p!($lb | None, $($x),+)
    };
    (_, $x:literal) => {
        {
            PermInner::S($x)
        }
    };
    (_, $($x:expr),+ $(,)?) => {
        p!(_lb | None, $($x),+)
    };
    (@sum $x:expr, $($xs:expr),+) => {
        $x.len() + p!(@sum $($xs),+);
    };
    (@sum $x:expr) => {
        $x.len()
    };
}

macro_rules! ph {
    ($hoist:ident ($lb:ident) = $($x:expr),+ $(,)?) => {
        $hoist = p!($lb | Some(stringify!($hoist)), $($x),+);
        let $hoist = &$hoist;
    };
    ($($hs:ident),+ $(,)?) => {
        $(let $hs;)+
    };
    (|$lb:ident| $($hoist:ident = [$($x:expr),+ $(,)?]; )+ ) => {
        $(ph!($hoist($lb) = $($x),+);)+
    }
}

macro_rules! c {
    () => {
        Vec::new()
    };
    (@inner $x:tt, $($xs:tt),+) => {
        {
            use $crate::macros::ConcatExt0;
            use $crate::macros::ConcatExt1;
            let len = $($xs.clen() + )+ 0_usize ;
            let mut ret = $x.make_reserve(len);
            $($xs.extend_other(&mut ret);)+
            ret
        }
    };
    (@add $x:tt $(+ $xs:tt)*) => {
        c!(@inner $x, $($xs),*)
    };
    (@add $x:tt $(+ $xs:expr)*) => {
        c!(@inner $x, $($xs),*)
    };
    (@comma $x:tt, $($xs:expr),*) => {
        c!(@inner $x, $($xs),*)
    };

    (@wee [] $($x:tt).+ $( ( $($y:tt),* ) )?, $($xs:tt)* ) => {
        {
            let bind = remove_paren!($($x).+ $( ( $($y),* ) )?) ;
            c!(@wee [bind] $($xs)*)
        }
    };
    (@wee [$($binds:tt)*] $($x:tt).+ $( ( $($y:tt),* ) )?, $($xs:tt)* ) => {
        {
            let bind = &remove_paren!($($x).+ $( ( $($y),* ) )?) ;
            c!(@wee [$($binds)* bind] $($xs)*)
        }
    };
    (@wee [$($binds:tt)*] $($x:tt).+ $( ( $($y:tt),* ) )?) => {
        c!(@wee [$($binds)*] $($x).+ $(($($y),*))? , )
        // call the above with an added comma            ^
    };
    (@wee [$bind:tt $($binds:tt)*]) => {
        {
            use $crate::macros::ConcatExt0;
            use $crate::macros::ConcatExt1;

            let total_len = $bind.clen() $(+ $binds.clen())*;
            let mut ret = $bind.make_reserve(total_len);
            $($binds.extend_other(&mut ret);)*
            ret
        }
    };

    (@c $($xs:tt)*) => {
        c!(@wee [] $($xs)*)
    };

    ($($x:tt).+ $( ( $($y:tt),* ) )? $( + $($xs:tt).+ $( ( $($ys:tt),* ) )?)* $(+)?) => {
        c!(@wee [] $($x).+ $(($($y),*))? $(, $($xs).+$(($($ys),*))?)* )
    };

    // probably not needed
    ($x:tt $( + $xs:tt)* $(+)?) => {
        c!(@wee [] $x, $($xs,)*)
    };
}

// prevent warnings for one layer of unnecessary parens
macro_rules! remove_paren {
    (($($t:tt)*)) => {
        $($t)*
    };
    ($($t:tt)*) => {
        $($t)*
    };
}

#[test]
fn reuses_alloc() {
    let mut v0 = Vec::with_capacity(32);
    v0.push(b'a');
    let ptr = v0.as_ptr();
    let v1 = vec![b'b'];
    let t = c![v0 + v1];
    assert_eq!(ptr, t.as_ptr());
    let t = c![t + b"cd" + b"ef" + b"ghi" + b"jklm" + b"nopq"];
    assert_eq!(ptr, t.as_ptr());
    assert_eq!(t, b"abcdefghijklmnopq");
}

#[test]
fn allows_references() {
    let mut v0 = Vec::with_capacity(32);
    v0.push(b'a');
    let ptr = v0.as_ptr();
    let v1 = vec![b'b'];
    let t = c![@c v0, (&v1)];
    assert_eq!(ptr, t.as_ptr());
    assert_eq!(t, b"ab");
}

/// ```compile_fail
/// let v0 = vec![1];
/// c![v0];
/// let _ = v0[0];
/// ```
#[allow(dead_code)]
fn move_vec() {}

#[test]
fn trailing_comma() {
    let a = c![@c 1, 2, 3];
    let b = c![@c 1, 2, 3, ];
    assert_eq!(a, b);
}
#[test]
fn messy_array_thing() {
    let f = |x: u8| x + 3;
    let v = vec![3, 4, 5];
    let t = c![([f(3)][0]) + 1 + v];
    assert_eq!(t, [6, 1, 3, 4, 5])
}

#[test]
fn thing() {
    let t = c![@add (Vec::from([1, 2, 3])) + b"abc".to_vec()];
    assert_eq!(t, b"\x01\x02\x03abc");
}

#[test]
fn example_where_new_version_is_better() {
    // Can't use @add
    #[allow(trivial_numeric_casts)]
    let t = c![[1, 2, 3] + b"abc" + (10 as u16).to_le_bytes() + b"a" + b"b"];
    assert_eq!(t, b"\x01\x02\x03abc\x0a\x00ab");
}

#[allow(unused_results)]
#[test]
fn doesnt_consume_non_first() {
    let t0 = vec![1];
    let t1 = vec![2];
    c![t0 + t1];
    assert_eq!(t1, [2]);
}

#[allow(clippy::cast_lossless)]
#[allow(trivial_numeric_casts)]
#[allow(unused_results)]
#[test]
fn macro_test() {
    let x = vec![1];
    c!(@add x + (1 + 2));
    let x = vec![1];
    c!(@add x + (1 + 2));
    let x = vec![1];
    c!(@add b"\xd9" + x);
    let x = vec![1];
    c!(@add [b'\xd9', b'\xd9'] + x);

    b"\xe8\xef\xff\xff\xff".clen();

    c![@add
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
        b"\xe8\xef\xff\xff\xff"   // call 0x8
    ];

    let x = vec![1];
    c![@add x + b"a" + b"a" + b"a"];

    let length = 0;
    c![b"\xb1" + (length as u8)];
    c![b"\x66\xb9" + (length as u16).to_le_bytes()];
    c![b"\xb9" + (length as u32).to_le_bytes()];
    let regnum = 5;
    let imm = 0_i32;
    let t = c![b"\x81" + (0xc0 + regnum) + (imm.to_le_bytes())];
    assert_eq!(t, [0x81, 0xc0 + 5, 0, 0, 0, 0]);
    c![@c b"\x81", [(0xc0 + regnum)], imm.to_le_bytes()];
    c![@c b"\x83", [(0xc0 + regnum)], (imm as u8).to_le_bytes()];
    let tmp = (8_u8, 7_u8);
    c![@c b"\x66\xb9" , (length as u16).to_le_bytes() , tmp.0 , tmp.0];
    c![(length as u16).to_le_bytes() + tmp.0 + tmp.0];
    c![[length + 10_u8] + tmp.0 + tmp.0];
    let v = vec![1];
    let w = vec![3, 4];
    let ret = c![@c w, v, tmp.0, tmp.1,];
    assert_eq!(ret, [3, 4, 1, 8, 7]);
}

pub(crate) trait ConcatExt0<T> {
    fn make_reserve(self, len: usize) -> Vec<T>;
}

impl<T: Copy> ConcatExt0<T> for Vec<T> {
    fn make_reserve(mut self, len: usize) -> Vec<T> {
        self.reserve(len);
        self
    }
}

impl<T: Copy> ConcatExt0<T> for &[T] {
    fn make_reserve(self, len: usize) -> Vec<T> {
        let mut ret = Vec::with_capacity(len + self.len());
        ret.extend_from_slice(self);
        ret
    }
}

impl<T: Copy + From<u8>> ConcatExt0<T> for T {
    fn make_reserve(self, len: usize) -> Vec<T> {
        let mut ret = Vec::with_capacity(len + 1);
        ret.push(self);
        ret
    }
}

pub(crate) trait ConcatExt1<T> {
    fn clen(&self) -> usize;
    fn extend_other(&self, other: &mut Vec<T>);
}

impl<T: Copy> ConcatExt1<T> for Vec<T> {
    fn clen(&self) -> usize {
        self.len()
    }
    fn extend_other(&self, other: &mut Vec<T>) {
        other.extend_from_slice(self)
    }
}

impl<T: Copy> ConcatExt1<T> for [T] {
    fn clen(&self) -> usize {
        self.len()
    }
    fn extend_other(&self, other: &mut Vec<T>) {
        other.extend_from_slice(self)
    }
}

// So we don't get arrays
impl<T: Copy + From<u8>> ConcatExt1<T> for T {
    fn clen(&self) -> usize {
        1
    }
    fn extend_other(&self, other: &mut Vec<T>) {
        other.push(*self)
    }
}

macro_rules! inherit {
    ($base:ident<$t:ty>) => {
        inherit!(@find_key @find_bad_keys @encode_block $base<$t>);
    };
    (@find_key $base:ident<$t:ty>) => {
        type FindKeyError = <$base<$t> as EncoderInherit<$t>>::FindKeyError;
        fn find_key<R: ::rand::Rng + ?Sized>(
            encoder: &$t,
            rng: &mut R,
            buf: &[u8],
            badchars: &[u8],
            decoder_stub: &DecoderStub,
        ) -> Result<u32, Self::FindKeyError> {
            <$base::<$t> as EncoderInherit<$t>>::find_key(encoder, rng, buf, badchars, decoder_stub)
        }
    };
    (@find_bad_keys $base:ident<$t:ty>) => {
        fn find_bad_keys(buf: &[u8], badchars: &[u8]) -> Vec<::std::collections::HashSet<u8>> {
            <$base::<$t> as EncoderInherit<$t>>::find_bad_keys(buf, badchars)
        }
    };
    (@encode_block $base:ident<$t:ty>) => {
        fn encode_block<R: ::rand::Rng +?Sized>(&self, rng: &mut R, key: &mut u32, block: &[u8], badchars: &[u8]) -> Vec<u8> {
            <$base::<$t> as EncoderInherit<$t>>::encode_block(&self.base, rng, key, block, badchars)
        }
    };
    ($(@$fn_name:ident)+ $base:ident<$t:ty>) => {
        $(inherit!(@$fn_name $base<$t>);)+
    };
}
