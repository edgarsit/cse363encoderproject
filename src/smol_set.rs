use crate::{logical::X86Register, logical_arena::pop_random};
use rand::{prelude::SliceRandom, Rng};
use std::{
    collections::HashSet, fmt::Debug, hash::Hash, iter::FromIterator, marker::PhantomData, ops,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SmolSet<T: SmolSetCanContain>(T::Ty);

impl<T> SmolSet<T>
where
    T: SmolSetCanContain,
{
    pub fn new() -> Self {
        Self(T::Ty::default())
    }
    /// returns if the set already contained this element
    pub fn insert(&mut self, other: T) -> bool {
        self.0.insert(other)
    }
    pub fn push(&mut self, other: T) {
        let _ = self.0.insert(other);
    }
    pub fn pop_random<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<T> {
        self.0.pop_random(rng)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn contains(&self, other: &T) -> bool {
        self.0.contains(other)
    }
}

impl<T> FromIterator<T> for SmolSet<T>
where
    T: SmolSetCanContain,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(T::Ty::from_iter(iter))
    }
}

impl<T> Extend<T> for SmolSet<T>
where
    T: SmolSetCanContain,
{
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.0.extend(iter)
    }
}

impl<'a, T> Extend<&'a T> for SmolSet<T>
where
    T: SmolSetCanContain + Copy + 'a,
{
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
        self.0.extend(iter.into_iter().copied())
    }
}

impl<T> IntoIterator for SmolSet<T>
where
    T: SmolSetCanContain,
{
    type Item = T;
    type IntoIter = <T::Ty as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a SmolSet<T>
where
    T: SmolSetCanContain,
    &'a T::Ty: IntoIterator,
{
    type Item = <&'a T::Ty as IntoIterator>::Item;
    type IntoIter = <&'a T::Ty as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        <&'a T::Ty as IntoIterator>::into_iter(&self.0)
    }
}

impl<T> Default for SmolSet<T>
where
    T: SmolSetCanContain,
{
    fn default() -> Self {
        Self(T::Ty::default())
    }
}

pub trait Container<T>:
    Debug + Clone + Default + FromIterator<T> + Extend<T> + IntoIterator<Item = T>
{
    fn insert(&mut self, other: T) -> bool {
        let ret = self.contains(&other);
        self.extend(Some(other));
        ret
    }
    fn contains(&self, other: &T) -> bool;
    fn pop_random<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<T>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone)]
pub struct VecSet<T>(Vec<T>);

impl<T> Default for VecSet<T> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl<T: Eq + Hash> FromIterator<T> for VecSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut ret = Self::default();
        ret.extend(iter);
        ret
    }
}

impl<T: Eq + Hash> Extend<T> for VecSet<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let mut inner = std::mem::replace(&mut self.0, Vec::new());
        inner.extend(iter);
        let uniq: HashSet<_> = inner.into_iter().collect();
        self.0 = uniq.into_iter().collect();
    }
}

impl<T: Debug + Copy + Eq + Hash> Container<T> for VecSet<T> {
    fn contains(&self, other: &T) -> bool {
        self.0.contains(other)
    }
    fn pop_random<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<T> {
        pop_random(rng, &mut self.0)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<T> IntoIterator for VecSet<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Debug + Copy + Eq + Hash, S: std::hash::BuildHasher + Default + Clone> Container<T>
    for HashSet<T, S>
{
    fn contains(&self, other: &T) -> bool {
        self.contains(other)
    }
    fn pop_random<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<T> {
        let t: Vec<_> = self.iter().collect();
        let t = **t.choose(rng)?;
        self.take(&t)
    }
    fn len(&self) -> usize {
        self.len()
    }
}

pub trait SmolSetCanContain: Sized {
    type Ty: Container<Self>;
}

impl SmolSetCanContain for u8 {
    type Ty = VecSet<Self>;
}

impl SmolSetCanContain for X86Register {
    type Ty = U8Container<X86Register>;
}

#[test]
fn size_is_one() {
    assert!(std::mem::size_of::<SmolSet<X86Register>>() == 1);
}

impl SmolSet<X86Register> {
    pub fn complement(&self) -> Self {
        let t = (self.0).0;
        Self(U8Container(!t, PhantomData))
    }
    pub const fn from_slice(s: &[X86Register]) -> Self {
        Self::from_slice_impl(U8Container::new(), s)
    }
    const fn from_slice_impl(ret: U8Container<X86Register>, s: &[X86Register]) -> Self {
        match s {
            [] => Self(ret),
            [x, xs @ ..] => Self::from_slice_impl(ret.const_set(x.reg_number(), true), xs),
        }
    }
    pub fn remove_item(&mut self, other: X86Register) {
        self.0.set(other.reg_number(), false)
    }
}

impl ops::BitAnd for SmolSet<X86Register> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        let ret = (self.0).0 & (rhs.0).0;
        Self(U8Container(ret, PhantomData))
    }
}
impl ops::BitOr for SmolSet<X86Register> {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        let ret = (self.0).0 | (rhs.0).0;
        Self(U8Container(ret, PhantomData))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct U8Container<T>(u8, PhantomData<T>);

impl<T> Default for U8Container<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> U8Container<T> {
    const fn new() -> Self {
        Self(0, PhantomData)
    }
    fn set(&mut self, place: u8, value: bool) {
        // maybe
        // https://graphics.stanford.edu/~seander/bithacks.html#ConditionalSetOrClearBitsWithoutBranching
        assert!(place < 8);

        let mask = 1 << place;
        if value {
            self.0 |= mask;
        } else {
            self.0 &= !mask;
        }
    }
    fn get(&self, place: u8) -> bool {
        let mask = 1 << place;
        (self.0 & mask) != 0
    }
    const fn const_set(self, place: u8, value: bool) -> Self {
        let m = 1 << place;
        let f = value as u8;
        let mut w = self.0;
        w ^= (!f ^ w) & m;
        Self(w, PhantomData)
    }
}

#[test]
fn a() {
    for i in 0..7 {
        let mut t = U8Container::<X86Register>::new();
        t.set(i, true);
        assert!(t.get(i))
    }
}

impl FromIterator<X86Register> for U8Container<X86Register> {
    fn from_iter<I: IntoIterator<Item = X86Register>>(iter: I) -> Self {
        let mut ret = Self::default();
        ret.extend(iter);
        ret
    }
}

impl Extend<X86Register> for U8Container<X86Register> {
    fn extend<I: IntoIterator<Item = X86Register>>(&mut self, iter: I) {
        <Self as SpecExtend<I::IntoIter>>::spec_extend(self, iter.into_iter())
    }
}

trait SpecExtend<I> {
    fn spec_extend(&mut self, iter: I);
}

impl<I> SpecExtend<I> for U8Container<X86Register>
where
    I: Iterator<Item = X86Register>,
{
    default fn spec_extend(&mut self, iter: I) {
        for x in iter {
            self.set(x.reg_number(), true);
        }
    }
}

impl SpecExtend<IntoIter<X86Register>> for U8Container<X86Register> {
    fn spec_extend(&mut self, iter: IntoIter<X86Register>) {
        self.0 |= (iter.0).0
    }
}

#[derive(Debug, Clone)]
pub struct IntoIter<T>(U8Container<T>);

impl Iterator for IntoIter<X86Register> {
    type Item = X86Register;
    fn next(&mut self) -> Option<Self::Item> {
        let t = &mut (self.0).0;
        if *t == 0 {
            return None;
        }
        let reg = t.trailing_zeros();
        debug_assert!(reg < 8);
        let ret = X86Register::from_number(reg as u8);
        *t &= *t - 1;
        ret
    }
}

impl IntoIterator for U8Container<X86Register> {
    type Item = X86Register;
    type IntoIter = IntoIter<X86Register>;
    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self)
    }
}
impl IntoIterator for &U8Container<X86Register> {
    type Item = X86Register;
    type IntoIter = IntoIter<X86Register>;
    fn into_iter(self) -> Self::IntoIter {
        // we are only a single u8
        IntoIter(self.clone())
    }
}

impl Container<X86Register> for U8Container<X86Register> {
    fn contains(&self, other: &X86Register) -> bool {
        self.get(other.reg_number())
    }
    fn pop_random<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Option<X86Register> {
        // https://stackoverflow.com/questions/61736649/in-java-how-to-get-positions-of-ones-in-reversed-binary-form-of-an-integer
        // https://stackoverflow.com/questions/35316422/pick-random-bit-from-32bit-value-in-o1-if-possible
        if self.0 == 0 {
            return None;
        }
        let max = self.0.count_ones();
        debug_assert!(max <= 8);
        let mut t = self.0;
        for _ in 0..rng.gen_range(0, max) {
            t &= t - 1;
        }
        debug_assert!(t != 0);
        let reg = t.trailing_zeros();
        assert!(reg < 8);
        self.set(reg as u8, false);
        let reg = X86Register::from_number(reg as u8);
        debug_assert!(reg.is_some());
        reg
    }
    fn len(&self) -> usize {
        let ret = self.0.count_ones();
        debug_assert!(ret <= 8);
        ret as usize
    }
}

#[cfg(test)]
#[quickcheck]
fn qc_pop_random_changes(n: u8) -> bool {
    use rand::thread_rng;
    let mut set = U8Container::<X86Register>(n, PhantomData);
    let set_clone = set.clone();
    if set.pop_random(&mut thread_rng()).is_some() {
        set != set_clone
    } else {
        true
    }
}
