use eyre::{bail, eyre};
use log::{debug, log_enabled, trace};
use netlink_bindings::utils;
use regex_automata::{
    Anchored,
    dfa::{
        Automaton,
        dense::{self, Config},
    },
    nfa::thompson,
    util::{alphabet::Unit, primitives::StateID, start},
};
use std::collections::HashSet;

use crate::{Direction, Matches, bpf};

type State = u32;
const DEAD: usize = 0;
const STATE_SIZE: usize = std::mem::size_of::<State>();

pub struct DFA {
    /// Number of different equivalence classes (including EOI)
    pub nclasses: usize,
    /// Equivalence class of EOI
    pub eoi_class: u16,
    /// Mapping: symbol -> equivalence class
    /// 256 bytes
    pub ec_table: Vec<u8>,
    /// Mapping: equivalence class -> first symbol
    pub ec_reps: Vec<Unit>,
    /// All equivalence classes (including EOI)
    pub ec_classes: Vec<usize>,
    /// A number of transitions dedicated to each state in the table
    pub stride: usize,
    /// Transition table: state_{i+1} = transition[state_i + ec_table[symbol]]
    pub trans: Vec<State>,
    /// Mapping: state -> pattern id
    pub pats: Vec<Vec<State>>,
    // dead: usize, // always zero
    /// fin_min <= matching state <= fin_max
    pub fin_min: State,
    pub fin_max: State,
    pub quit: Vec<State>,
    pub start: State,
}

impl std::fmt::Debug for DFA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DFA")
            .field("nclasses", &self.nclasses)
            .field("eoi_class", &self.eoi_class)
            // .field("ec_table", &self.ec_table)
            .field("ec_reps", &self.ec_reps)
            .field("ec_classes", &self.ec_classes)
            .field("fin_min", &self.fin_min)
            .field("fin_max", &self.fin_max)
            .field("stride", &self.stride)
            .field("quit", &self.quit)
            .field("start", &self.start)
            .field("pats", &self.pats)
            .field("transitions", &DFATransitions(self))
            .finish()
    }
}

struct DFATransitions<'a>(&'a DFA);
impl std::fmt::Debug for DFATransitions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dfa = self.0;
        writeln!(f)?;
        for i in (0..dfa.trans.len()).step_by(dfa.stride) {
            write!(f, "    {i:0>6}:")?;
            if i == DEAD {
                write!(f, " DEAD")?;
            }
            if i == dfa.start as usize {
                write!(f, " START")?;
            }
            if dfa.quit.contains(&(i as State)) {
                write!(f, " QUIT")?;
            }
            if dfa.fin_min as usize <= i && i <= dfa.fin_max as usize {
                write!(f, " FIN")?;
            }
            for &j in &dfa.ec_classes {
                let next = dfa.trans[i + j];
                if next != 0 {
                    write!(f, " {:?} => {}", dfa.ec_reps[j], next)?;
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

pub fn build_dfa(pats: &[String], reverse: bool) -> eyre::Result<dense::DFA<Vec<u32>>> {
    debug!(
        "Building {} DFA for paterns: {pats:?}",
        if reverse { "reverse" } else { "forward" }
    );

    dense::DFA::builder()
        .thompson(thompson::Config::new().reverse(reverse).shrink(true))
        .configure(
            Config::new()
                .start_kind(regex_automata::dfa::StartKind::Anchored)
                .dfa_size_limit(Some(bpf::DFA_MAX_SIZE as usize))
                .accelerate(false),
        )
        .build_many(pats)
        .map_err(|e| eyre!("{e}"))
}

pub fn extract_dfa(pats: &[String]) -> eyre::Result<DFA> {
    extract(&build_dfa(pats, true)?, Anchored::Yes)
}

pub fn extract(dfa: &dense::DFA<Vec<u32>>, anchored: Anchored) -> eyre::Result<DFA> {
    trace!("dense::DFA: {dfa:?}");

    let mut ec_table = vec![0u8; 256];
    let mut ec_classes = HashSet::new();
    ec_classes.insert(dfa.byte_classes().eoi().as_usize());
    for i in 0..ec_table.len() {
        let ec = dfa.byte_classes().get(i as u8);
        ec_table[i] = ec;
        ec_classes.insert(ec as usize);
    }

    let ec_classes: Vec<_> = ec_classes.into_iter().collect();
    let ec_reps: Vec<_> = dfa.byte_classes().representatives(..).collect();

    let start = dfa
        .start_state(&start::Config::new().anchored(anchored))
        .map_err(|e| eyre!("{e}"))?;

    let mut trans = Vec::new();
    let mut dead = Vec::new();
    let mut quit = Vec::new();
    let mut fin = Vec::new();
    let mut pats = Vec::new();

    let mut i = 0;
    let mut max = start;
    while i < max.as_usize() + dfa.stride() {
        let this = StateID::new(i).unwrap();
        let next = dfa.next_state(this, 0);
        trans.push(next.as_usize());

        if dfa.is_dead_state(this) {
            dead.push(this);
        }

        if dfa.is_quit_state(this) {
            quit.push(this);
        }

        if dfa.is_match_state(this) {
            fin.push(this);
            let mut matches = Vec::new();
            for i in 0..dfa.match_len(this) {
                matches.push(dfa.match_pattern(this, i).as_usize() as State);
            }
            pats.push(matches);
        } else if !pats.is_empty() {
            pats.push(Vec::new());
        }

        max = StateID::max(next, max);
        i += 1;
    }

    if trans.len() * STATE_SIZE > bpf::DFA_MAX_SIZE as usize {
        bail!("Constructed DFA has too many states: {}", trans.len());
    }

    if fin.is_empty() {
        bail!("Expected at least 1 final state.");
    }

    let fin_min = fin.iter().map(|s| s.as_usize() as State).min().unwrap();
    let fin_max = fin.iter().map(|s| s.as_usize() as State).max().unwrap();

    for i in fin_min..=fin_max {
        assert!(dfa.is_match_state(StateID::new(i as usize).unwrap()));
    }

    let pats_len = pats.len() - pats.iter().rev().take_while(|p| p.is_empty()).count();
    pats.truncate(pats_len);

    for i in 0..dfa.stride() {
        assert_eq!(trans[i], 0); // Assert that for any char: (dead state, char) -> dead
    }

    assert_eq!(dead, vec![StateID::new(DEAD).unwrap()]);

    Ok(DFA {
        fin_min,
        fin_max,
        quit: quit.iter().map(|&t| t.as_usize() as State).collect(),
        nclasses: dfa.alphabet_len(),
        eoi_class: dfa.byte_classes().eoi().as_usize() as u16,
        ec_table,
        ec_reps,
        ec_classes,
        pats,
        trans: trans.iter().map(|&t| t as State).collect(),
        stride: dfa.stride(),
        start: start.as_usize() as State,
    })
}

pub fn encode_dfa(
    pats: &[String],
    arena: &mut Vec<u8>,
    pat_id_map: &[usize],
    matches: &Matches,
) -> eyre::Result<bpf::DFA> {
    let dfa = extract_dfa(pats)?;

    trace!("dfa::DFA: {dfa:?}");

    utils::align(arena);

    let dfa_off = arena.len() as u32;
    assert_eq!(dfa.ec_table.len(), 256);

    arena.extend_from_slice(&dfa.ec_table);
    arena.reserve(dfa.trans.len() * STATE_SIZE);
    for t in &dfa.trans {
        arena.extend(t.to_ne_bytes());
    }

    utils::align(arena);

    let table_len = dfa.pats.iter().map(|p| p.len()).sum();
    let mut redirect_table = Vec::with_capacity(table_len);
    let mut uid_table = Vec::with_capacity(table_len);
    let mut match_id_table = Vec::with_capacity(table_len);

    let match_slices_off = arena.len() as u32;
    arena.reserve(dfa.pats.len() * STATE_SIZE);

    for pats in &dfa.pats {
        assert_eq!(uid_table.len(), match_id_table.len());

        let off = uid_table.len() as u32;
        let len = pats.len() as u32;

        for &pat_id in pats {
            let m_id = pat_id_map[pat_id as usize];
            let m = &matches.matches[m_id];
            redirect_table.push(match m.direction {
                Direction::bypass => 0u8,
                Direction::redirect => 1u8,
            });
            uid_table.push(m.uid);
            match_id_table.push(m_id as u32);
        }

        arena.extend(off.to_ne_bytes());
        arena.extend(len.to_ne_bytes());
    }

    let redirect_table_off = arena.len() as u32;
    for val in &redirect_table {
        arena.extend(val.to_ne_bytes());
    }

    let uid_table_off = arena.len() as u32;
    for val in &uid_table {
        arena.extend(val.to_ne_bytes());
    }

    let match_id_table_off = arena.len() as u32;
    for val in &match_id_table {
        arena.extend(val.to_ne_bytes());
    }

    if log_enabled!(log::Level::Trace) {
        dbg!(&dfa.pats, &redirect_table, &uid_table, &match_id_table);
    }

    let dfa = bpf::DFA {
        dfa_off,
        start: dfa.start,
        eoi: dfa.eoi_class,
        fin_min: dfa.fin_min,
        fin_max: dfa.fin_max,
        match_slices_off,
        redirect_table_off,
        match_id_table_off,
        uid_table_off,
    };

    debug!("bpf::DFA: {dfa:?}");
    if log_enabled!(log::Level::Trace) {
        debug!("Dumping {} bytes of bpf::DFA:", arena.len());
        netlink_bindings::utils::dump_hex(&arena[..]);
    }

    Ok(dfa)
}
