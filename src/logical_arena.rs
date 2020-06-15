use crate::{logical::X86Register, rex::badchar_index, smol_set::SmolSet, AsEscape};
use petgraph::{
    algo::is_cyclic_directed,
    dot::{Config, Dot},
    graph::{Graph, NodeIndex},
    Direction,
};
use rand::seq::SliceRandom;
use rand::Rng;
use std::{
    collections::HashMap,
    fmt,
    process::{Command, Stdio},
};

#[derive(Debug)]
pub struct Context<'a> {
    graph: Graph<LogicalBlock<'a>, ()>,
    regs: HashMap<LogicalRegister, Option<X86Register>>,
    /// Logical Register Count
    lr_count: usize,
    debug_logical_register: Vec<&'static str>,
}

impl<'a> Context<'a> {
    pub fn new() -> Self {
        Self {
            graph: Graph::new(),
            regs: HashMap::new(),
            lr_count: 0,
            debug_logical_register: Vec::new(),
        }
    }

    pub fn add_reg(
        &mut self,
        name: &'static str,
        reg: impl Into<Option<X86Register>>,
    ) -> LogicalRegister {
        let lr = LogicalRegister::new(self.lr_count);
        self.debug_logical_register.push(name);
        let prev = self.regs.insert(lr, reg.into());
        debug_assert!(prev.is_none());
        self.lr_count += 1;
        lr
    }

    pub fn add_block(&mut self, name: &'static str, perms: Vec<PermInner<'a>>) -> LogicalBlockRef {
        debug_assert!(perms.windows(2).all(|v| match v {
            [a, b] => a.len() == b.len(),
            _ => unreachable!(),
        }));
        let lb = LogicalBlock::new(name, perms);
        let idx = self.graph.add_node(lb);
        LogicalBlockRef::new(idx)
    }

    pub fn depends_on(&mut self, a: LogicalBlockRef, b: LogicalBlockRef) {
        let _ = self.graph.add_edge(a.idx, b.idx, ());
    }

    // 3 error modes:
    // out of registers : programming error
    // GenerateBlockListError::OutOfPerms user error
    // could not find without badchars: user error
    pub fn generate<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        saved_regs: &SmolSet<X86Register>,
        badchars: &[u8],
    ) -> Result<Vec<u8>, GenerateError> {
        if false {
            self.debug_dot();
        }
        let mut tmp;
        let mut last_error = None;
        for _ in 0..1024 {
            tmp = self.do_generate(rng, saved_regs, badchars);
            match tmp {
                Ok(buf) => {
                    if badchar_index(&buf, badchars).is_none() {
                        return Ok(buf);
                    }
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(GenerateError(last_error))
    }

    fn debug_dot(&self) {
        use std::io::Write;
        let mut child =
            Command::new(r#"C:\Users\Edgar\Downloads\graphviz-2.38\release\bin\dot.exe"#)
                .args(&["-Tpng", "-O"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::piped())
                .spawn()
                .expect("Could not spawn graphviz");
        write!(
            child
                .stdin
                .as_mut()
                .expect("Could not get stdin of graphviz"),
            "{:?}",
            Dot::with_attr_getters(
                &self.graph,
                &[Config::EdgeNoLabel, Config::NodeNoLabel],
                &|_, _| { String::new() },
                &|_, node| {
                    let (_, lb) = node;
                    format!("label = {}", lb.name)
                }
            )
        )
        .expect("Could not write to stdin of graphviz");
        assert!(child.wait().unwrap().success());
    }

    fn do_generate<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        saved_regs: &SmolSet<X86Register>,
        badchars: &[u8],
    ) -> Result<Vec<u8>, DoGenerateError> {
        // NB: state holds loop invariant parts
        let mut state = State::new(saved_regs, &self.regs);

        let (perm_list, offsets, max_offset) = self.generate_block_list(rng, badchars)?;

        let mut ret = Vec::with_capacity(max_offset);
        let mut old_len = 0;
        for (idx, perm) in perm_list {
            while let Err(e) = {
                let llb = LiveLogicalBlock::new(&state, &offsets, max_offset);
                debug_assert!(ret.len() == offsets[&idx]);
                perm.write(&mut ret, &llb)
            } {
                ret.truncate(old_len);
                let t = state
                    .regnums
                    .pop_random(rng)
                    .ok_or(DoGenerateError::OutOfRegisters)?;
                let prev = state.current_reg_assignment.insert(e.reg, t);
                debug_assert!(prev.is_none());
            }
            debug_assert_eq!(perm.len(), ret.len() - old_len);
            old_len = ret.len();
        }

        Ok(ret)
    }

    fn generate_block_list<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        badchars: &[u8],
    ) -> Result<
        (
            Vec<(NodeIndex, &PermInner)>,
            HashMap<NodeIndex, usize>,
            usize,
        ),
        GenerateBlockListError,
    > {
        // We could preallocate roots by counting nodes added and subtract edges added to externals
        // Nodes start external
        // if a->b, b looses flag and count--
        // more effort than its worth probably
        debug_assert!(!is_cyclic_directed(&self.graph));

        let mut roots: Vec<_> = self.graph.externals(Direction::Incoming).collect();
        let mut ret = Vec::with_capacity(self.graph.raw_nodes().len());

        while let Some(poped) = pop_random(rng, &mut roots) {
            roots.extend(self.graph.neighbors(poped));
            let perm = self.graph[poped]
                .rand_perm(rng, badchars)
                .ok_or(GenerateBlockListError::OutOfPerms)?;
            ret.push((poped, perm));
        }

        ret.reverse();
        let mut curr_offset = 0;
        let mut offsets = HashMap::new();
        for &(idx, perm) in &ret {
            let t = offsets.insert(idx, curr_offset);
            debug_assert!(t.is_none());
            curr_offset += perm.len();
        }

        Ok((ret, offsets, curr_offset))
    }

    pub fn end_block(&self) -> EndBlock {
        let _ = self;
        EndBlock {}
    }
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct EndBlock {}

// from rand
// Sample a number uniformly between 0 and `ubound`. Uses 32-bit sampling where
// possible, primarily in order to produce the same output on 32-bit and 64-bit
// platforms.
fn gen_index<R: Rng + ?Sized>(rng: &mut R, ubound: usize) -> usize {
    if ubound <= (core::u32::MAX as usize) {
        rng.gen_range(0, ubound as u32) as usize
    } else {
        rng.gen_range(0, ubound)
    }
}

pub fn pop_random<R: Rng + ?Sized, T>(rng: &mut R, v: &mut Vec<T>) -> Option<T> {
    if v.is_empty() {
        None
    } else {
        Some(v.swap_remove(gen_index(rng, v.len())))
    }
}

#[derive(Debug)]
struct LogicalBlock<'a> {
    name: &'static str,
    perms: Vec<PermInner<'a>>,
}

impl<'a> LogicalBlock<'a> {
    fn new(name: &'static str, perms: Vec<PermInner<'a>>) -> Self {
        Self { name, perms }
    }

    fn rand_perm<R: Rng + ?Sized>(&self, rng: &mut R, badchars: &[u8]) -> Option<&PermInner<'a>> {
        if badchars.is_empty() {
            self.perms.choose(rng)
        } else {
            self.rand_perm_badchars(rng, badchars)
        }
    }

    fn rand_perm_badchars<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        badchars: &[u8],
    ) -> Option<&PermInner<'a>> {
        for p in self.perms.choose_multiple(rng, self.perms.len()) {
            let buf = match p {
                PermInner::F(_, _, _) => return Some(p),
                PermInner::S(s) => s,
                PermInner::V(v) => v.as_slice(),
            };
            if badchar_index(buf, badchars).is_none() {
                return Some(p);
            }
        }
        None
    }
}

pub enum PermInner<'a> {
    S(&'a [u8]),
    V(Vec<u8>),
    F(
        usize,
        Box<dyn Fn(&LiveLogicalBlock, &mut Vec<u8>) -> Result<(), InvalidRegisterError> + 'a>,
        Option<&'static str>,
    ),
}

impl<'a> PermInner<'a> {
    pub fn from_fn<F>(len: usize, f: F, name: Option<&'static str>) -> Self
    where
        F: Fn(&LiveLogicalBlock, &mut Vec<u8>) -> Result<(), InvalidRegisterError> + 'a,
    {
        Self::F(len, Box::new(f), name)
    }
}

impl Writer for PermInner<'_> {
    fn len(&self) -> usize {
        match self {
            Self::S(s) => s.len(),
            Self::V(v) => v.len(),
            &Self::F(len, _, _) => len,
        }
    }

    fn write(&self, buf: &mut Vec<u8>, llb: &LiveLogicalBlock) -> Result<(), InvalidRegisterError> {
        match self {
            Self::S(s) => {
                buf.extend_from_slice(s);
                Ok(())
            }
            Self::V(v) => {
                buf.extend_from_slice(v);
                Ok(())
            }
            Self::F(_, f, _) => f(llb, buf),
        }
    }
}

impl fmt::Debug for PermInner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PermInner::S(s) => write!(f, "PermInner::S(b\"{}\")", AsEscape(s)),
            PermInner::V(v) => write!(f, "PermInner::V(b\"{}\".to_vec())", AsEscape(v)),
            PermInner::F(len, _, name) => {
                write!(f, "PermInner::F({}, {{{{closure}}}}, {:?})", len, name)
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct LogicalBlockRef {
    idx: NodeIndex,
}

impl LogicalBlockRef {
    fn new(idx: NodeIndex) -> Self {
        Self { idx }
    }
    pub fn add_perms<'a>(&mut self, context: &mut Context<'a>, perms: Vec<PermInner<'a>>) {
        context.graph[self.idx].perms.extend(perms)
    }
}

#[derive(Debug, Clone)]
struct State {
    regnums: SmolSet<X86Register>,
    current_reg_assignment: HashMap<LogicalRegister, X86Register>,
}

impl State {
    fn new(
        saved_regs: &SmolSet<X86Register>,
        current_reg_assignment: &HashMap<LogicalRegister, Option<X86Register>>,
    ) -> Self {
        if cfg!(debug_assertions) {
            let mut assigned_regs = SmolSet::<X86Register>::new();
            for (_, &reg) in current_reg_assignment.iter() {
                if let Some(reg) = reg {
                    assert!(!assigned_regs.insert(reg));
                }
            }
            assert_eq!(saved_regs.clone(), assigned_regs);
        }
        Self {
            regnums: saved_regs.complement(),
            current_reg_assignment: current_reg_assignment
                .iter()
                .filter_map(|(&lr, &reg)| reg.map(|reg| (lr, reg)))
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct LiveLogicalBlock<'d, 'e> {
    state: &'d State,
    offsets: &'e HashMap<NodeIndex, usize>,
    curr_offset: usize,
}

impl<'d, 'e> LiveLogicalBlock<'d, 'e> {
    fn new(state: &'d State, offsets: &'e HashMap<NodeIndex, usize>, curr_offset: usize) -> Self {
        Self {
            state,
            offsets,
            curr_offset,
        }
    }

    pub fn regnum_of(&self, reg: LogicalRegister) -> Result<u8, InvalidRegisterError> {
        match self.state.current_reg_assignment.get(&reg) {
            Some(&v) => Ok(X86Register::reg_number(v)),
            None => Err(InvalidRegisterError::new(reg)),
        }
    }

    pub fn offset_of(&self, reg: impl LogicalBlockRefOrEndBlock) -> usize {
        reg.try_offset_of(self).unwrap()
    }
}

pub trait LogicalBlockRefOrEndBlock: Copy {
    fn try_offset_of(&self, llb: &LiveLogicalBlock) -> Option<usize>;
}

impl LogicalBlockRefOrEndBlock for LogicalBlockRef {
    fn try_offset_of(&self, llb: &LiveLogicalBlock) -> Option<usize> {
        llb.offsets.get(&self.idx).copied()
    }
}
impl LogicalBlockRefOrEndBlock for EndBlock {
    fn try_offset_of(&self, llb: &LiveLogicalBlock) -> Option<usize> {
        Some(llb.curr_offset)
    }
}

#[derive(Debug, Clone)]
pub struct InvalidRegisterError {
    reg: LogicalRegister,
}

impl InvalidRegisterError {
    const fn new(reg: LogicalRegister) -> Self {
        Self { reg }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DoGenerateError {
    #[error("{0}")]
    GenerateBlockListError(#[from] GenerateBlockListError),
    #[error("Internal error: out of registers")]
    OutOfRegisters,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum GenerateBlockListError {
    #[error("could not generate permutation without badchars")]
    OutOfPerms,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("Error while generating blocks")]
pub struct GenerateError(Option<DoGenerateError>);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct LogicalRegister {
    id: usize,
}

impl LogicalRegister {
    const fn new(id: usize) -> Self {
        Self { id }
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait Writer {
    fn len(&self) -> usize;
    fn write(
        &self,
        buf: &mut Vec<u8>,
        other: &LiveLogicalBlock,
    ) -> Result<(), InvalidRegisterError>;
}

impl<W: Writer + ?Sized> Writer for &W {
    fn len(&self) -> usize {
        (*self).len()
    }
    fn write(
        &self,
        buf: &mut Vec<u8>,
        other: &LiveLogicalBlock,
    ) -> Result<(), InvalidRegisterError> {
        (*self).write(buf, other)
    }
}

impl Writer for [u8] {
    fn len(&self) -> usize {
        self.len()
    }
    fn write(
        &self,
        buf: &mut Vec<u8>,
        other: &LiveLogicalBlock,
    ) -> Result<(), InvalidRegisterError> {
        let _ = other;
        buf.extend_from_slice(self);
        Ok(())
    }
}
