#![feature(never_type)]
#![feature(array_value_iter)]
#![feature(vec_remove_item)]
#![feature(specialization)]
#![feature(test)]
#![feature(const_fn)]
#![feature(const_if_match)]
//
#![deny(bare_trait_objects)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]
//
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    // clippy::cargo
)]
//
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
//
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::shadow_unrelated)]
#![allow(clippy::type_complexity)]
#![allow(clippy::enum_glob_use)]
//
#![allow(clippy::if_not_else)]
#![allow(clippy::use_self)]
#![allow(clippy::new_without_default)]
#![allow(clippy::into_iter_on_ref)]

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[macro_use]
pub mod macros;
pub mod logical;

pub mod add_sub;
pub mod alpha_mixed;
pub mod encoder;
pub mod jmp_call_additive;
pub mod logical_arena;
pub mod rex;
pub mod shikata_ga_nai;
pub mod smol_set;

use std::fmt;

pub struct AsEscape<'a>(pub &'a [u8]);

impl fmt::Debug for AsEscape<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for AsEscape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.0 {
            write!(f, "\\x{:02x}", b)?;
        }
        Ok(())
    }
}
