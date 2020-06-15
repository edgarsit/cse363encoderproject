pub mod arch;
pub mod encoder;
pub mod encoding;
pub mod exceptions;

pub fn badchar_index(buf: &[u8], badchars: &[u8]) -> Option<usize> {
    for &badchar in badchars {
        let pos = buf.iter().position(|&x| x == badchar);
        if pos.is_some() {
            return pos;
        }
    }
    None
}
