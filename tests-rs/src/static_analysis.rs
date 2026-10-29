// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Static binary analysis against the seccomp filters, ported from
//! `tests/framework/static_analysis.py`.
//!
//! The python module disassembles a binary with `objdump`, parses the assembly,
//! back-propagates register values to recover syscall numbers and arguments, and
//! finally reports the seccomp rules that no actual invocation can match.
//!
//! Python's `Instruction` / `Architecture` class hierarchies become the
//! [`Architecture`] enum plus [`Instruction`] values that carry their own
//! architecture, and its two exception classes become [`BackpropError`].

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

use crate::{defs, utils};

/// Forward-propagation operation applied to a value recovered by back-propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transform {
    /// `add dst, src, #imm`: adds `imm` to the back-propagated value.
    Add(i64),
    /// `sub dst, src, #imm`: subtracts `imm` from the back-propagated value.
    Sub(i64),
    /// `movk dst, #imm, lsl #shift`: replaces 16 bits at `shift` with `imm`.
    Movk {
        /// Immediate that is shifted into place.
        immediate: i64,
        /// Left shift of the 16 bit field, in bits.
        shift: u32,
    },
}

impl Transform {
    /// Applies the operation to a back-propagated value.
    pub fn apply(&self, value: i64) -> i64 {
        match *self {
            Transform::Add(imm) => value.wrapping_add(imm),
            Transform::Sub(imm) => value.wrapping_sub(imm),
            Transform::Movk { immediate, shift } => {
                // 16 bit field at `shift`, matching python's
                // `0b1111_1111_1111_1111 << shift` mask.
                let mask = 0xffff_i64.wrapping_shl(shift);
                (value & !mask) | immediate.wrapping_shl(shift)
            }
        }
    }
}

/// Failure modes of register back-propagation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackpropError {
    /// The instruction touches the register of interest but is not understood.
    #[error(
        "Encountered unsupported instruction during backpropagation which affects a register of interest ({register}): {instruction}"
    )]
    UnsupportedInstruction {
        /// Instruction rendered the way objdump printed it.
        instruction: String,
        /// Register we were trying to back-propagate.
        register: String,
    },
    /// The beginning of the function was reached without finding an immediate.
    #[error(
        "Backpropagation reached beginning of function definition while backpropagating {register}. Maybe it is a parameter itself?"
    )]
    ReachedStartOfFn {
        /// Registers still being back-propagated when the start was reached.
        register: String,
    },
}

/// Outcome of back-propagating a single instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    /// The instruction loads this immediate into the register.
    Immediate(i64),
    /// The value lives in another register (possibly the same one).
    Register(String),
    /// The value lives in another register and needs forward-propagation.
    Transformed {
        /// Register holding the value before this instruction.
        register: String,
        /// Operation to apply once the value is known.
        transform: Transform,
    },
}

/// Value of a register at some point of a function, or why it is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterValue {
    /// The register value could be determined statically.
    Known(i64),
    /// The register value could not be determined.
    Unresolved(BackpropError),
}

impl RegisterValue {
    /// Returns the known value, if any.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            RegisterValue::Known(value) => Some(*value),
            RegisterValue::Unresolved(_) => None,
        }
    }

    /// Returns the error explaining why the value is unknown, if any.
    pub fn error(&self) -> Option<&BackpropError> {
        match self {
            RegisterValue::Known(_) => None,
            RegisterValue::Unresolved(err) => Some(err),
        }
    }
}

/// Instruction set architecture targeted by the analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// `x86_64`, with the System V integer argument registers.
    X86_64,
    /// `aarch64`, with the AAPCS64 integer argument registers.
    Aarch64,
}

impl Architecture {
    /// Architecture matching the host, like python's `platform.processor()`.
    pub fn host() -> Self {
        match defs::host_arch() {
            "x86_64" => Architecture::X86_64,
            _ => Architecture::Aarch64,
        }
    }

    /// Architecture from its canonical name (`x86_64` / `aarch64`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "x86_64" => Some(Architecture::X86_64),
            "aarch64" => Some(Architecture::Aarch64),
            _ => None,
        }
    }

    /// Canonical name, identical to the seccomp `Arch` name.
    pub fn name(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Aarch64 => "aarch64",
        }
    }

    /// Prefix objdump uses for inline comments on this architecture.
    pub fn comment_prefix(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "#",
            Architecture::Aarch64 => "//",
        }
    }

    /// Register holding the syscall number.
    pub fn syscall_nr_register(&self) -> &'static str {
        match self {
            Architecture::X86_64 => "%eax",
            Architecture::Aarch64 => "x8",
        }
    }

    /// Registers (in order) holding the syscall arguments.
    pub fn syscall_argument_registers(&self) -> &'static [&'static str] {
        const X86_64: [&str; 6] = ["%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9"];
        const AARCH64: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
        match self {
            Architecture::X86_64 => &X86_64,
            Architecture::Aarch64 => &AARCH64,
        }
    }

    /// Registers (in order) holding the arguments of a normal function call.
    pub fn fn_call_argument_registers(&self) -> &'static [&'static str] {
        const X86_64: [&str; 6] = ["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"];
        const AARCH64: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
        match self {
            Architecture::X86_64 => &X86_64,
            Architecture::Aarch64 => &AARCH64,
        }
    }

    /// Registers partially aliasing `reg`, widest first.
    ///
    /// On x86, `%rdi` yields `[%rdi, %edi, %di]`; on aarch64, `x1` yields
    /// `[x1, w1]`.
    pub fn generalize_reg(&self, reg: &str) -> Vec<String> {
        match self {
            Architecture::X86_64 => {
                const SUFFIXES: [&str; 8] = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
                const PREFIXES: [&str; 8] =
                    ["%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15"];
                for suffix in SUFFIXES {
                    if reg.ends_with(suffix) {
                        return vec![
                            format!("%r{suffix}"),
                            format!("%e{suffix}"),
                            format!("%{suffix}"),
                        ];
                    }
                }
                for prefix in PREFIXES {
                    if reg.starts_with(prefix) {
                        return vec![
                            prefix.to_string(),
                            format!("{prefix}d"),
                            format!("{prefix}w"),
                        ];
                    }
                }
                vec![reg.to_string()]
            }
            Architecture::Aarch64 => match aarch64_register_number(reg) {
                Some(nr) => vec![format!("x{nr}"), format!("w{nr}")],
                None => vec![reg.to_string()],
            },
        }
    }

    /// Parses one objdump line with this architecture's syntax.
    pub fn parse_instruction(&self, line: &str) -> Instruction {
        Instruction::parse(line, *self)
    }

    /// Determines the value of `register` at the end of `instructions`.
    pub fn determine_register_value(
        &self,
        instructions: &[Instruction],
        register: &str,
    ) -> std::result::Result<i64, BackpropError> {
        let mut looking_for = self.generalize_reg(register);
        let mut transforms: Vec<Transform> = Vec::new();

        for insn in instructions.iter().rev() {
            for reg in looking_for.clone() {
                match insn.backpropagate_register(&reg) {
                    Err(err) => return Err(err),
                    Ok(RegValue::Immediate(value)) => {
                        // The value is known: forward propagate the transforms
                        // in the order the instructions were executed.
                        return Ok(transforms
                            .iter()
                            .fold(value, |acc, transform| transform.apply(acc)));
                    }
                    Ok(RegValue::Transformed {
                        register,
                        transform,
                    }) => {
                        transforms.insert(0, transform);
                        looking_for = self.generalize_reg(&register);
                        break;
                    }
                    Ok(RegValue::Register(next)) => {
                        if next != reg {
                            looking_for = self.generalize_reg(&next);
                            break;
                        }
                    }
                }
            }
        }

        Err(BackpropError::ReachedStartOfFn {
            register: looking_for.join(","),
        })
    }

    /// Resolves a syscall number to its name on this architecture.
    pub fn resolve_syscall(&self, nr: i64) -> Option<&'static str> {
        let table = self.syscall_table();
        table
            .binary_search_by_key(&nr, |(number, _)| *number)
            .ok()
            .map(|index| table[index].1)
    }

    /// Resolves a syscall name to its number on this architecture.
    pub fn resolve_syscall_number(&self, name: &str) -> Option<i64> {
        self.syscall_table()
            .iter()
            .find(|(_, candidate)| *candidate == name)
            .map(|(nr, _)| *nr)
    }

    fn syscall_table(&self) -> &'static [(i64, &'static str)] {
        match self {
            Architecture::X86_64 => X86_64_SYSCALLS,
            Architecture::Aarch64 => AARCH64_SYSCALLS,
        }
    }
}

/// Parses the `<digits>` part of `x12` / `w3`; `None` for other registers.
fn aarch64_register_number(reg: &str) -> Option<u32> {
    let rest = reg.strip_prefix('x').or_else(|| reg.strip_prefix('w'))?;
    if rest.is_empty() || rest.len() > 2 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse::<u32>().ok()
}

/// A single disassembled instruction in objdump's default syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    arch: Architecture,
    mnemonic: String,
    args: Vec<String>,
}

impl Instruction {
    /// Builds an instruction from its mnemonic and already split operands.
    pub fn new(arch: Architecture, mnemonic: &str, args: Vec<String>) -> Self {
        Self {
            arch,
            mnemonic: mnemonic.to_string(),
            args,
        }
    }

    /// Parses a raw objdump line, stripping comments and splitting operands.
    pub fn parse(line: &str, arch: Architecture) -> Self {
        let mut cleaned = comment_regex(arch).replace_all(line, "").into_owned();
        while cleaned.ends_with([' ', '\t']) {
            cleaned.pop();
        }
        let mut parts = cleaned.splitn(2, char::is_whitespace);
        let mnemonic = parts.next().unwrap_or_default().trim().to_string();
        let args = parts
            .next()
            .map(|rest| {
                rest.split(',')
                    .map(|arg| arg.trim().to_string())
                    .filter(|arg| !arg.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Self::new(arch, &mnemonic, args)
    }

    /// Architecture this instruction was parsed for.
    pub fn arch(&self) -> Architecture {
        self.arch
    }

    /// Instruction mnemonic (`mov`, `call`, ...).
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Operands of the instruction, without surrounding whitespace.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Whether the instruction is a subroutine call or an unconditional jump.
    pub fn is_call(&self) -> bool {
        match self.arch {
            Architecture::X86_64 => matches!(self.mnemonic.as_str(), "call" | "jmp"),
            Architecture::Aarch64 => matches!(self.mnemonic.as_str(), "b" | "bl"),
        }
    }

    /// Whether the instruction traps into the kernel.
    pub fn is_syscall(&self) -> bool {
        match self.arch {
            Architecture::X86_64 => self.mnemonic == "syscall",
            Architecture::Aarch64 => {
                self.mnemonic == "svc" && self.args.len() == 1 && self.args[0] == "#0x0"
            }
        }
    }

    /// Instruction rendered without spaces, matching python's `str(insn)`.
    pub fn text(&self) -> String {
        format!("{} {}", self.mnemonic, self.args.join(","))
    }

    /// Back-propagates `reg` through this single instruction.
    pub fn backpropagate_register(
        &self,
        reg: &str,
    ) -> std::result::Result<RegValue, BackpropError> {
        match self.arch {
            Architecture::X86_64 => self.backpropagate_x86_64(reg),
            Architecture::Aarch64 => self.backpropagate_aarch64(reg),
        }
    }

    fn backpropagate_x86_64(&self, reg: &str) -> std::result::Result<RegValue, BackpropError> {
        // Simplifying assumption (as in python): an instruction does not modify
        // a register it does not reference.
        if !x86_referenced_registers(&self.text())
            .iter()
            .any(|candidate| candidate == reg)
        {
            return Ok(RegValue::Register(reg.to_string()));
        }

        match self.mnemonic.as_str() {
            "mov" => {
                if self.args.len() != 2 {
                    return Err(self.unsupported(reg));
                }
                let (src, dst) = (&self.args[0], &self.args[1]);
                if dst != reg {
                    return Ok(RegValue::Register(reg.to_string()));
                }
                if let Some(value) = parse_hex_operand(src) {
                    return Ok(RegValue::Immediate(value));
                }
                if is_x86_register(src) {
                    return Ok(RegValue::Register(src.clone()));
                }
                Err(self.unsupported(reg))
            }
            "xor" => {
                if self.args.len() != 2 {
                    return Err(self.unsupported(reg));
                }
                if self.args[0] == self.args[1] {
                    // `xor reg,reg` zeroes the register.
                    return Ok(RegValue::Immediate(0));
                }
                Err(self.unsupported(reg))
            }
            // A push does not modify any register we track.
            "push" => Ok(RegValue::Register(reg.to_string())),
            _ => Err(self.unsupported(reg)),
        }
    }

    fn backpropagate_aarch64(&self, reg: &str) -> std::result::Result<RegValue, BackpropError> {
        if !aarch64_referenced_registers(&self.text())
            .iter()
            .any(|candidate| candidate == reg)
        {
            return Ok(RegValue::Register(reg.to_string()));
        }

        match self.mnemonic.as_str() {
            "mov" => {
                if self.args.len() != 2 {
                    return Err(self.unsupported(reg));
                }
                let (dst, src) = (&self.args[0], &self.args[1]);
                if dst != reg {
                    return Ok(RegValue::Register(reg.to_string()));
                }
                if let Some(value) = parse_hex_operand(src) {
                    return Ok(RegValue::Immediate(value));
                }
                if src == "xzr" || src == "wzr" {
                    // See the aarch64 documentation on the zero registers.
                    return Ok(RegValue::Immediate(0));
                }
                if aarch64_register_number(src).is_some() {
                    return Ok(RegValue::Register(src.clone()));
                }
                Err(self.unsupported(reg))
            }
            "movk" => {
                if !matches!(self.args.len(), 2 | 3) {
                    return Err(self.unsupported(reg));
                }
                let Some(immediate) = parse_hex_operand(&self.args[1]) else {
                    return Err(self.unsupported(reg));
                };
                let shift = match self.args.get(2) {
                    Some(operand) => match parse_shift_operand(operand) {
                        Some(shift) => shift,
                        None => return Err(self.unsupported(reg)),
                    },
                    None => 0,
                };
                Ok(RegValue::Transformed {
                    register: reg.to_string(),
                    transform: Transform::Movk { immediate, shift },
                })
            }
            "add" | "sub" => {
                if self.args.len() != 3 {
                    return Err(self.unsupported(reg));
                }
                let (dst, src) = (&self.args[0], &self.args[1]);
                if dst != reg {
                    return Ok(RegValue::Register(reg.to_string()));
                }
                // Only constant additions can be followed, because the
                // back-propagation cannot follow two registers at once.
                let Some(immediate) = parse_hex_operand(&self.args[2]) else {
                    return Err(self.unsupported(reg));
                };
                let transform = if self.mnemonic == "add" {
                    Transform::Add(immediate)
                } else {
                    Transform::Sub(immediate)
                };
                Ok(RegValue::Transformed {
                    register: src.clone(),
                    transform,
                })
            }
            _ => Err(self.unsupported(reg)),
        }
    }

    fn unsupported(&self, reg: &str) -> BackpropError {
        BackpropError::UnsupportedInstruction {
            instruction: self.text(),
            register: reg.to_string(),
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.mnemonic, self.args.join(","))
    }
}

/// Parses the numeric part of an immediate operand (`$0x10`, `#0x10`, `12`).
fn parse_hex_operand(operand: &str) -> Option<i64> {
    let stripped = operand.trim().trim_start_matches(['$', '#']);
    let digits = stripped.strip_prefix("0x").unwrap_or(stripped);
    if digits.is_empty() {
        return None;
    }
    i64::from_str_radix(digits, 16).ok()
}

/// Parses the shift of an `lsl #<shift>` operand.
fn parse_shift_operand(operand: &str) -> Option<u32> {
    let stripped = operand.trim();
    let rest = stripped.strip_prefix("lsl").unwrap_or(stripped);
    rest.trim().trim_start_matches('#').parse::<u32>().ok()
}

/// Whether the operand is a full x86_64 register name (`%eax`, `%r10d`).
fn is_x86_register(operand: &str) -> bool {
    x86_operand_regex()
        .find(operand)
        .map(|m| m.as_str() == operand)
        .unwrap_or(false)
}

fn x86_referenced_registers(text: &str) -> Vec<String> {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"(%[a-z0-9]{2,4})(\W|)").expect("valid regex"));
    re.captures_iter(text)
        .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn aarch64_referenced_registers(text: &str) -> Vec<String> {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| regex::Regex::new(r"(\s|,)([wx]\d{1,2})(\W|)").expect("valid regex"));
    re.captures_iter(text)
        .filter_map(|caps| caps.get(2).map(|m| m.as_str().to_string()))
        .collect()
}

fn x86_operand_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^%\w{2,4}$").expect("valid regex"))
}

fn comment_regex(arch: Architecture) -> &'static regex::Regex {
    static X86: OnceLock<regex::Regex> = OnceLock::new();
    static ARM: OnceLock<regex::Regex> = OnceLock::new();
    match arch {
        Architecture::X86_64 => {
            X86.get_or_init(|| regex::Regex::new(r"\s+#.*").expect("valid regex"))
        }
        Architecture::Aarch64 => {
            ARM.get_or_init(|| regex::Regex::new(r"\s+//.*").expect("valid regex"))
        }
    }
}

/// Names of functions treated as raw syscall wrappers.
pub const SYSCALL_WRAPPERS: [&str; 3] = ["syscall", "__syscall_cp", "__syscall_cp_c"];

/// A libc wrapper that always issues one specific syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpecificSyscallWrapper {
    /// Syscall the wrapper issues.
    pub syscall: &'static str,
    /// Number of syscall arguments the wrapper takes from its caller.
    pub nargs: usize,
    /// Argument transformations applied before the syscall (`index`, operation).
    pub arg_transform: &'static [(usize, Transform)],
}

/// Looks up a [`SpecificSyscallWrapper`] by function name.
pub fn specific_syscall_wrapper(name: &str) -> Option<&'static SpecificSyscallWrapper> {
    static WRAPPERS: OnceLock<BTreeMap<&'static str, SpecificSyscallWrapper>> = OnceLock::new();
    WRAPPERS.get_or_init(build_specific_wrappers).get(name)
}

fn build_specific_wrappers() -> BTreeMap<&'static str, SpecificSyscallWrapper> {
    let mut map = BTreeMap::new();
    map.insert(
        "ioctl",
        SpecificSyscallWrapper {
            syscall: "ioctl",
            nargs: 3,
            arg_transform: &[],
        },
    );
    map.insert(
        "__mmap",
        SpecificSyscallWrapper {
            syscall: "mmap",
            nargs: 6,
            arg_transform: &[],
        },
    );
    map.insert(
        "socket",
        SpecificSyscallWrapper {
            syscall: "socket",
            nargs: 3,
            arg_transform: &[],
        },
    );
    map.insert(
        "__madvise",
        SpecificSyscallWrapper {
            syscall: "madvise",
            nargs: 3,
            arg_transform: &[],
        },
    );
    // musl's tcsetattr issues ioctl with TCSETS/TCSETSW/TCSETSF, so the request
    // argument is offset by 0x5402.
    map.insert(
        "tcsetattr",
        SpecificSyscallWrapper {
            syscall: "ioctl",
            nargs: 3,
            arg_transform: &[(1, Transform::Add(0x5402))],
        },
    );
    map
}

/// A single function of the binary, e.g. as delimited by DWARF debug info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// Symbol name, without the angle brackets objdump prints around it.
    pub name: String,
    /// Instructions of the function, in program order.
    pub instructions: Vec<Instruction>,
    arch: Architecture,
}

impl Function {
    /// Builds an empty function for `arch`.
    pub fn new(name: &str, arch: Architecture) -> Self {
        Self {
            name: name.to_string(),
            instructions: Vec::new(),
            arch,
        }
    }

    /// Architecture the function's instructions were parsed for.
    pub fn arch(&self) -> Architecture {
        self.arch
    }

    /// Determines the values of `registers` when the `i`-th instruction runs.
    pub fn resolve_registers_before_insn(
        &self,
        i: usize,
        registers: &[&str],
    ) -> BTreeMap<String, RegisterValue> {
        let prefix = &self.instructions[..i.min(self.instructions.len())];
        let mut resolved = BTreeMap::new();
        for reg in registers {
            let value = match self.arch.determine_register_value(prefix, reg) {
                Ok(value) => RegisterValue::Known(value),
                Err(err) => RegisterValue::Unresolved(err),
            };
            resolved.insert((*reg).to_string(), value);
        }
        resolved
    }
}

/// Parses `objdump -d` output into the list of contained functions.
pub fn parse_objdump_output(output: &str, arch: Architecture) -> Vec<Function> {
    static SYMBOL: OnceLock<regex::Regex> = OnceLock::new();
    let symbol_regex = SYMBOL.get_or_init(|| regex::Regex::new(r"^<(.+)>:$").expect("valid regex"));

    let mut functions: Vec<Function> = Vec::new();
    let mut current: Option<Function> = None;

    // Skip the "file format" line and the blank line after it.
    for line in output.lines().skip(2) {
        let line = line.trim();

        // Empty lines and section announcements separate functions.
        if line.is_empty() || line.starts_with("Disassembly of section") {
            if let Some(function) = current.take() {
                functions.push(function);
            }
            continue;
        }

        if let Some(caps) = symbol_regex.captures(line) {
            if let Some(function) = current.take() {
                functions.push(function);
            }
            current = Some(Function::new(&caps[1], arch));
            continue;
        }

        match current.as_mut() {
            Some(function) => function.instructions.push(arch.parse_instruction(line)),
            None => eprintln!("Unexpectedly found data outside of function. Skipping line {line}"),
        }
    }

    if let Some(function) = current.take() {
        functions.push(function);
    }

    functions
}

/// Syscall name to the recovered invocations (`None` for unknown arguments).
pub type SyscallInvocations = BTreeMap<String, Vec<Vec<Option<i64>>>>;

/// Whether `name` is a function whose body is treated as a syscall itself.
pub fn is_syscall_wrapper(name: &str) -> bool {
    SYSCALL_WRAPPERS.contains(&name) || specific_syscall_wrapper(name).is_some()
}

/// Recovers all syscall invocations of the given functions.
pub fn find_syscalls_in_functions(
    functions: &[Function],
    arch: Architecture,
) -> SyscallInvocations {
    let mut found_syscalls: SyscallInvocations = BTreeMap::new();

    for function in functions {
        // Skip the wrappers themselves: their arguments are the arguments of
        // the function, which this analysis cannot recover.
        if is_syscall_wrapper(&function.name) {
            continue;
        }

        for (i, insn) in function.instructions.iter().enumerate() {
            let Some((syscall_nr, syscall_args)) = resolve_invocation(function, i, insn, arch)
            else {
                continue;
            };

            let Some(nr) = syscall_nr.as_i64() else {
                eprintln!(
                    "Failed to resolve syscall number for instruction {insn} in function {}: {}",
                    function.name,
                    syscall_nr
                        .error()
                        .map(ToString::to_string)
                        .unwrap_or_default()
                );
                continue;
            };

            let Some(syscall_name) = arch.resolve_syscall(nr) else {
                eprintln!(
                    "Failed to resolve name of syscall {nr} for instruction {insn} in function {}",
                    function.name
                );
                continue;
            };

            found_syscalls
                .entry(syscall_name.to_string())
                .or_default()
                .push(syscall_args);
        }
    }

    found_syscalls
}

/// Resolves the syscall number and arguments of an instruction, if it is one.
fn resolve_invocation(
    function: &Function,
    i: usize,
    insn: &Instruction,
    arch: Architecture,
) -> Option<(RegisterValue, Vec<Option<i64>>)> {
    if insn.is_syscall() {
        let mut registers = vec![arch.syscall_nr_register()];
        registers.extend_from_slice(arch.syscall_argument_registers());
        let mut resolved = function.resolve_registers_before_insn(i, &registers);
        let nr = resolved.remove(arch.syscall_nr_register())?;
        let args = collect_args(&resolved, arch.syscall_argument_registers(), None);
        return Some((nr, args));
    }

    if !insn.is_call() {
        return None;
    }

    let called = called_function_name(insn)?;
    let fn_regs = arch.fn_call_argument_registers();

    if SYSCALL_WRAPPERS.contains(&called.as_str()) {
        let mut resolved = function.resolve_registers_before_insn(i, fn_regs);
        // The syscall number is passed like a normal first argument, because
        // `%eax` is not used for function arguments on x86_64.
        let nr = resolved.remove(fn_regs[0])?;
        let args = collect_args(&resolved, &fn_regs[1..], None);
        return Some((nr, args));
    }

    let wrapper = specific_syscall_wrapper(&called)?;
    let nr = arch.resolve_syscall_number(wrapper.syscall)?;
    let resolved = function.resolve_registers_before_insn(i, fn_regs);
    let mut args = collect_args(&resolved, fn_regs, Some(wrapper.nargs));

    if args.iter().all(Option::is_none) {
        eprintln!(
            "Could not resolve any argument for syscall wrapper {called} in function {}",
            function.name
        );
    }

    // Some wrappers transform an argument before issuing the syscall.
    for (index, transform) in wrapper.arg_transform.iter() {
        if let Some(Some(value)) = args.get_mut(*index) {
            *value = transform.apply(*value);
        }
    }

    Some((RegisterValue::Known(nr), args))
}

/// Collects the argument values of `registers`, truncated to `nargs` if given.
fn collect_args(
    resolved: &BTreeMap<String, RegisterValue>,
    registers: &[&str],
    nargs: Option<usize>,
) -> Vec<Option<i64>> {
    registers
        .iter()
        .take(nargs.unwrap_or(registers.len()))
        .map(|reg| resolved.get(*reg).and_then(RegisterValue::as_i64))
        .collect()
}

/// Extracts the callee name from an objdump `call <target>` operand.
fn called_function_name(insn: &Instruction) -> Option<String> {
    let target = insn.args().first()?;
    let name = target.trim_start_matches('<').trim_end_matches('>');
    (!name.is_empty()).then(|| name.to_string())
}

/// Statically analyzes `binary_path` and returns the syscalls it issues.
pub fn find_syscalls_in_binary(binary_path: &Path) -> Result<SyscallInvocations> {
    let arch = Architecture::host();
    let path = binary_path.display().to_string();
    let output = utils::check_output_args(&[
        "objdump",
        "--demangle=rust",
        "-d",
        &path,
        "--no-show-raw-insn",
        "--no-addresses",
    ])
    .with_context(|| format!("disassembling {path}"))?;

    let functions = parse_objdump_output(&output.stdout, arch);
    Ok(find_syscalls_in_functions(&functions, arch))
}

/// One argument constraint of a seccomp rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgConstraint {
    /// Allowed value (`val` in the filter JSON).
    pub val: u64,
    /// Bitmask for `masked_eq` comparisons, `None` for plain `eq`.
    pub mask: Option<u64>,
}

/// Argument constraints of one seccomp rule, keyed by argument index.
pub type RuleArgs = BTreeMap<usize, ArgConstraint>;

/// Seccomp allow-list: syscall name to the rules that allow it.
pub type SeccompAllowlist = BTreeMap<String, Vec<RuleArgs>>;

/// Reads the seccomp filters at `path` as an allow-list.
///
/// Each syscall maps to its list of rules; every rule maps the constrained
/// argument indices to their allowed value and optional bitmask.
pub fn load_seccomp_rules(path: &Path) -> Result<SeccompAllowlist> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("reading seccomp filters {}", path.display()))?;
    let filters: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("parsing seccomp filters {}", path.display()))?;

    let mut allowlist: SeccompAllowlist = BTreeMap::new();

    for context in ["vcpu", "vmm", "api"] {
        let Some(list) = filters
            .get(context)
            .and_then(|value| value.get("filter"))
            .and_then(|value| value.as_array())
        else {
            bail!(
                "seccomp filters in {} have no '{context}.filter' list",
                path.display()
            );
        };

        for seccomp_filter in list {
            let Some(syscall_name) = seccomp_filter.get("syscall").and_then(|v| v.as_str()) else {
                bail!("seccomp filter in {} has no 'syscall'", path.display());
            };

            let mut arg_constraints = RuleArgs::new();
            let args = seccomp_filter
                .get("args")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            for arg in args {
                let index = arg
                    .get("index")
                    .and_then(|value| value.as_u64())
                    .ok_or_else(|| missing_field(syscall_name, "index", path))?;
                let op = arg.get("op").cloned().unwrap_or(serde_json::Value::Null);
                let mask = if let Some(mask) = op.get("masked_eq").and_then(|v| v.as_u64()) {
                    Some(mask)
                } else if op.as_str() == Some("eq") {
                    None
                } else {
                    bail!(
                        "Unknown seccomp op '{op}' for syscall '{syscall_name}' arg {index}. \
                         Please add support for this op in load_seccomp_rules and arg_matches."
                    );
                };
                let val = arg
                    .get("val")
                    .and_then(|value| value.as_u64())
                    .ok_or_else(|| missing_field(syscall_name, "val", path))?;
                arg_constraints.insert(index as usize, ArgConstraint { val, mask });
            }

            allowlist
                .entry(syscall_name.to_string())
                .or_default()
                .push(arg_constraints);
        }
    }

    Ok(allowlist)
}

fn missing_field(syscall: &str, field: &str, path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "seccomp rule for syscall '{syscall}' in {} has no '{field}'",
        path.display()
    )
}

/// Path of the seccomp filter JSON for the host architecture.
pub fn host_seccomp_json_path() -> PathBuf {
    defs::seccomp_json_dir().join(format!("{}-unknown-linux-musl.json", defs::host_arch()))
}

/// Loads the seccomp filters shipped for the host architecture.
pub fn load_host_seccomp_rules() -> Result<SeccompAllowlist> {
    load_seccomp_rules(&host_seccomp_json_path())
}

/// Rules that static analysis can never observe, keyed by syscall name.
pub fn known_superfluous_rules() -> &'static BTreeMap<&'static str, Vec<RuleArgs>> {
    static RULES: OnceLock<BTreeMap<&'static str, Vec<RuleArgs>>> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut map: BTreeMap<&'static str, Vec<RuleArgs>> = BTreeMap::new();
        // `restart_syscall` is inserted by the kernel at runtime, so it is not
        // present in the binary itself.
        map.insert("restart_syscall", vec![RuleArgs::new()]);
        map
    })
}

/// Checks whether an actual argument value matches a seccomp rule constraint.
///
/// For plain `eq` (`mask` is `None`) this is `actual == val`; for `masked_eq`
/// it is `(actual & mask) == val`.
pub fn arg_matches(actual: i64, val: u64, mask: Option<u64>) -> bool {
    match mask {
        None => actual as u64 == val,
        Some(mask) => ((actual as u64) & mask) == val,
    }
}

/// Computes the seccomp rules that no recovered invocation can match.
///
/// A rule is reported when, for every actual invocation of its syscall, the
/// rule constrains some argument to a value the invocation never passes. A rule
/// without any constraint is never reported, because it allows all arguments.
pub fn determine_unneeded_seccomp_rules(
    seccomp_rules: &SeccompAllowlist,
    found_syscalls: &SyscallInvocations,
) -> Vec<(String, RuleArgs)> {
    let superfluous = known_superfluous_rules();
    let mut redundant_rules = Vec::new();

    for (syscall, rules) in seccomp_rules {
        for allowed_arguments in rules {
            if superfluous
                .get(syscall.as_str())
                .map(|known| known.contains(allowed_arguments))
                .unwrap_or(false)
            {
                continue;
            }

            let rule_not_needed = match found_syscalls.get(syscall) {
                // No invocation at all: the universal quantification holds
                // vacuously, so the rule cannot be needed.
                None => true,
                Some(invocations) => invocations.iter().all(|actual| {
                    allowed_arguments
                        .iter()
                        .any(|(index, constraint)| match actual.get(*index) {
                            Some(Some(value)) => {
                                !arg_matches(*value, constraint.val, constraint.mask)
                            }
                            // Unknown or absent argument values cannot prove
                            // that the rule is unmatched.
                            _ => false,
                        })
                }),
            };

            if rule_not_needed {
                redundant_rules.push((syscall.clone(), allowed_arguments.clone()));
            }
        }
    }

    redundant_rules
}

// Syscall number to name tables, generated from the kernel uapi headers
// (`asm/unistd_64.h` and `asm-generic/unistd.h`). They hold what libseccomp's
// `resolve_syscall` returns for the two architectures.
#[rustfmt::skip]
const X86_64_SYSCALLS: &[(i64, &str)] = &[
    (0, "read"), (1, "write"), (2, "open"), (3, "close"), (4, "stat"),
    (5, "fstat"), (6, "lstat"), (7, "poll"), (8, "lseek"), (9, "mmap"),
    (10, "mprotect"), (11, "munmap"), (12, "brk"), (13, "rt_sigaction"), (14, "rt_sigprocmask"),
    (15, "rt_sigreturn"), (16, "ioctl"), (17, "pread64"), (18, "pwrite64"), (19, "readv"),
    (20, "writev"), (21, "access"), (22, "pipe"), (23, "select"), (24, "sched_yield"),
    (25, "mremap"), (26, "msync"), (27, "mincore"), (28, "madvise"), (29, "shmget"),
    (30, "shmat"), (31, "shmctl"), (32, "dup"), (33, "dup2"), (34, "pause"),
    (35, "nanosleep"), (36, "getitimer"), (37, "alarm"), (38, "setitimer"), (39, "getpid"),
    (40, "sendfile"), (41, "socket"), (42, "connect"), (43, "accept"), (44, "sendto"),
    (45, "recvfrom"), (46, "sendmsg"), (47, "recvmsg"), (48, "shutdown"), (49, "bind"),
    (50, "listen"), (51, "getsockname"), (52, "getpeername"), (53, "socketpair"), (54, "setsockopt"),
    (55, "getsockopt"), (56, "clone"), (57, "fork"), (58, "vfork"), (59, "execve"),
    (60, "exit"), (61, "wait4"), (62, "kill"), (63, "uname"), (64, "semget"),
    (65, "semop"), (66, "semctl"), (67, "shmdt"), (68, "msgget"), (69, "msgsnd"),
    (70, "msgrcv"), (71, "msgctl"), (72, "fcntl"), (73, "flock"), (74, "fsync"),
    (75, "fdatasync"), (76, "truncate"), (77, "ftruncate"), (78, "getdents"), (79, "getcwd"),
    (80, "chdir"), (81, "fchdir"), (82, "rename"), (83, "mkdir"), (84, "rmdir"),
    (85, "creat"), (86, "link"), (87, "unlink"), (88, "symlink"), (89, "readlink"),
    (90, "chmod"), (91, "fchmod"), (92, "chown"), (93, "fchown"), (94, "lchown"),
    (95, "umask"), (96, "gettimeofday"), (97, "getrlimit"), (98, "getrusage"), (99, "sysinfo"),
    (100, "times"), (101, "ptrace"), (102, "getuid"), (103, "syslog"), (104, "getgid"),
    (105, "setuid"), (106, "setgid"), (107, "geteuid"), (108, "getegid"), (109, "setpgid"),
    (110, "getppid"), (111, "getpgrp"), (112, "setsid"), (113, "setreuid"), (114, "setregid"),
    (115, "getgroups"), (116, "setgroups"), (117, "setresuid"), (118, "getresuid"), (119, "setresgid"),
    (120, "getresgid"), (121, "getpgid"), (122, "setfsuid"), (123, "setfsgid"), (124, "getsid"),
    (125, "capget"), (126, "capset"), (127, "rt_sigpending"), (128, "rt_sigtimedwait"), (129, "rt_sigqueueinfo"),
    (130, "rt_sigsuspend"), (131, "sigaltstack"), (132, "utime"), (133, "mknod"), (134, "uselib"),
    (135, "personality"), (136, "ustat"), (137, "statfs"), (138, "fstatfs"), (139, "sysfs"),
    (140, "getpriority"), (141, "setpriority"), (142, "sched_setparam"), (143, "sched_getparam"), (144, "sched_setscheduler"),
    (145, "sched_getscheduler"), (146, "sched_get_priority_max"), (147, "sched_get_priority_min"), (148, "sched_rr_get_interval"), (149, "mlock"),
    (150, "munlock"), (151, "mlockall"), (152, "munlockall"), (153, "vhangup"), (154, "modify_ldt"),
    (155, "pivot_root"), (156, "_sysctl"), (157, "prctl"), (158, "arch_prctl"), (159, "adjtimex"),
    (160, "setrlimit"), (161, "chroot"), (162, "sync"), (163, "acct"), (164, "settimeofday"),
    (165, "mount"), (166, "umount2"), (167, "swapon"), (168, "swapoff"), (169, "reboot"),
    (170, "sethostname"), (171, "setdomainname"), (172, "iopl"), (173, "ioperm"), (174, "create_module"),
    (175, "init_module"), (176, "delete_module"), (177, "get_kernel_syms"), (178, "query_module"), (179, "quotactl"),
    (180, "nfsservctl"), (181, "getpmsg"), (182, "putpmsg"), (183, "afs_syscall"), (184, "tuxcall"),
    (185, "security"), (186, "gettid"), (187, "readahead"), (188, "setxattr"), (189, "lsetxattr"),
    (190, "fsetxattr"), (191, "getxattr"), (192, "lgetxattr"), (193, "fgetxattr"), (194, "listxattr"),
    (195, "llistxattr"), (196, "flistxattr"), (197, "removexattr"), (198, "lremovexattr"), (199, "fremovexattr"),
    (200, "tkill"), (201, "time"), (202, "futex"), (203, "sched_setaffinity"), (204, "sched_getaffinity"),
    (205, "set_thread_area"), (206, "io_setup"), (207, "io_destroy"), (208, "io_getevents"), (209, "io_submit"),
    (210, "io_cancel"), (211, "get_thread_area"), (212, "lookup_dcookie"), (213, "epoll_create"), (214, "epoll_ctl_old"),
    (215, "epoll_wait_old"), (216, "remap_file_pages"), (217, "getdents64"), (218, "set_tid_address"), (219, "restart_syscall"),
    (220, "semtimedop"), (221, "fadvise64"), (222, "timer_create"), (223, "timer_settime"), (224, "timer_gettime"),
    (225, "timer_getoverrun"), (226, "timer_delete"), (227, "clock_settime"), (228, "clock_gettime"), (229, "clock_getres"),
    (230, "clock_nanosleep"), (231, "exit_group"), (232, "epoll_wait"), (233, "epoll_ctl"), (234, "tgkill"),
    (235, "utimes"), (236, "vserver"), (237, "mbind"), (238, "set_mempolicy"), (239, "get_mempolicy"),
    (240, "mq_open"), (241, "mq_unlink"), (242, "mq_timedsend"), (243, "mq_timedreceive"), (244, "mq_notify"),
    (245, "mq_getsetattr"), (246, "kexec_load"), (247, "waitid"), (248, "add_key"), (249, "request_key"),
    (250, "keyctl"), (251, "ioprio_set"), (252, "ioprio_get"), (253, "inotify_init"), (254, "inotify_add_watch"),
    (255, "inotify_rm_watch"), (256, "migrate_pages"), (257, "openat"), (258, "mkdirat"), (259, "mknodat"),
    (260, "fchownat"), (261, "futimesat"), (262, "newfstatat"), (263, "unlinkat"), (264, "renameat"),
    (265, "linkat"), (266, "symlinkat"), (267, "readlinkat"), (268, "fchmodat"), (269, "faccessat"),
    (270, "pselect6"), (271, "ppoll"), (272, "unshare"), (273, "set_robust_list"), (274, "get_robust_list"),
    (275, "splice"), (276, "tee"), (277, "sync_file_range"), (278, "vmsplice"), (279, "move_pages"),
    (280, "utimensat"), (281, "epoll_pwait"), (282, "signalfd"), (283, "timerfd_create"), (284, "eventfd"),
    (285, "fallocate"), (286, "timerfd_settime"), (287, "timerfd_gettime"), (288, "accept4"), (289, "signalfd4"),
    (290, "eventfd2"), (291, "epoll_create1"), (292, "dup3"), (293, "pipe2"), (294, "inotify_init1"),
    (295, "preadv"), (296, "pwritev"), (297, "rt_tgsigqueueinfo"), (298, "perf_event_open"), (299, "recvmmsg"),
    (300, "fanotify_init"), (301, "fanotify_mark"), (302, "prlimit64"), (303, "name_to_handle_at"), (304, "open_by_handle_at"),
    (305, "clock_adjtime"), (306, "syncfs"), (307, "sendmmsg"), (308, "setns"), (309, "getcpu"),
    (310, "process_vm_readv"), (311, "process_vm_writev"), (312, "kcmp"), (313, "finit_module"), (314, "sched_setattr"),
    (315, "sched_getattr"), (316, "renameat2"), (317, "seccomp"), (318, "getrandom"), (319, "memfd_create"),
    (320, "kexec_file_load"), (321, "bpf"), (322, "execveat"), (323, "userfaultfd"), (324, "membarrier"),
    (325, "mlock2"), (326, "copy_file_range"), (327, "preadv2"), (328, "pwritev2"), (329, "pkey_mprotect"),
    (330, "pkey_alloc"), (331, "pkey_free"), (332, "statx"), (333, "io_pgetevents"), (334, "rseq"),
    (335, "uretprobe"), (336, "uprobe"), (424, "pidfd_send_signal"), (425, "io_uring_setup"), (426, "io_uring_enter"),
    (427, "io_uring_register"), (428, "open_tree"), (429, "move_mount"), (430, "fsopen"), (431, "fsconfig"),
    (432, "fsmount"), (433, "fspick"), (434, "pidfd_open"), (435, "clone3"), (436, "close_range"),
    (437, "openat2"), (438, "pidfd_getfd"), (439, "faccessat2"), (440, "process_madvise"), (441, "epoll_pwait2"),
    (442, "mount_setattr"), (443, "quotactl_fd"), (444, "landlock_create_ruleset"), (445, "landlock_add_rule"), (446, "landlock_restrict_self"),
    (447, "memfd_secret"), (448, "process_mrelease"), (449, "futex_waitv"), (450, "set_mempolicy_home_node"), (451, "cachestat"),
    (452, "fchmodat2"), (453, "map_shadow_stack"), (454, "futex_wake"), (455, "futex_wait"), (456, "futex_requeue"),
    (457, "statmount"), (458, "listmount"), (459, "lsm_get_self_attr"), (460, "lsm_set_self_attr"), (461, "lsm_list_modules"),
    (462, "mseal"), (463, "setxattrat"), (464, "getxattrat"), (465, "listxattrat"), (466, "removexattrat"),
    (467, "open_tree_attr"), (468, "file_getattr"), (469, "file_setattr"), (470, "listns"), (471, "rseq_slice_yield"),
];

#[rustfmt::skip]
const AARCH64_SYSCALLS: &[(i64, &str)] = &[
    (0, "io_setup"), (1, "io_destroy"), (2, "io_submit"), (3, "io_cancel"), (4, "io_getevents"),
    (5, "setxattr"), (6, "lsetxattr"), (7, "fsetxattr"), (8, "getxattr"), (9, "lgetxattr"),
    (10, "fgetxattr"), (11, "listxattr"), (12, "llistxattr"), (13, "flistxattr"), (14, "removexattr"),
    (15, "lremovexattr"), (16, "fremovexattr"), (17, "getcwd"), (18, "lookup_dcookie"), (19, "eventfd2"),
    (20, "epoll_create1"), (21, "epoll_ctl"), (22, "epoll_pwait"), (23, "dup"), (24, "dup3"),
    (25, "fcntl"), (26, "inotify_init1"), (27, "inotify_add_watch"), (28, "inotify_rm_watch"), (29, "ioctl"),
    (30, "ioprio_set"), (31, "ioprio_get"), (32, "flock"), (33, "mknodat"), (34, "mkdirat"),
    (35, "unlinkat"), (36, "symlinkat"), (37, "linkat"), (38, "renameat"), (39, "umount2"),
    (40, "mount"), (41, "pivot_root"), (42, "nfsservctl"), (43, "statfs"), (44, "fstatfs"),
    (45, "truncate"), (46, "ftruncate"), (47, "fallocate"), (48, "faccessat"), (49, "chdir"),
    (50, "fchdir"), (51, "chroot"), (52, "fchmod"), (53, "fchmodat"), (54, "fchownat"),
    (55, "fchown"), (56, "openat"), (57, "close"), (58, "vhangup"), (59, "pipe2"),
    (60, "quotactl"), (61, "getdents64"), (62, "lseek"), (63, "read"), (64, "write"),
    (65, "readv"), (66, "writev"), (67, "pread64"), (68, "pwrite64"), (69, "preadv"),
    (70, "pwritev"), (71, "sendfile"), (72, "pselect6"), (73, "ppoll"), (74, "signalfd4"),
    (75, "vmsplice"), (76, "splice"), (77, "tee"), (78, "readlinkat"), (79, "fstatat"),
    (80, "fstat"), (81, "sync"), (82, "fsync"), (83, "fdatasync"), (84, "sync_file_range"),
    (85, "timerfd_create"), (86, "timerfd_settime"), (87, "timerfd_gettime"), (88, "utimensat"), (89, "acct"),
    (90, "capget"), (91, "capset"), (92, "personality"), (93, "exit"), (94, "exit_group"),
    (95, "waitid"), (96, "set_tid_address"), (97, "unshare"), (98, "futex"), (99, "set_robust_list"),
    (100, "get_robust_list"), (101, "nanosleep"), (102, "getitimer"), (103, "setitimer"), (104, "kexec_load"),
    (105, "init_module"), (106, "delete_module"), (107, "timer_create"), (108, "timer_gettime"), (109, "timer_getoverrun"),
    (110, "timer_settime"), (111, "timer_delete"), (112, "clock_settime"), (113, "clock_gettime"), (114, "clock_getres"),
    (115, "clock_nanosleep"), (116, "syslog"), (117, "ptrace"), (118, "sched_setparam"), (119, "sched_setscheduler"),
    (120, "sched_getscheduler"), (121, "sched_getparam"), (122, "sched_setaffinity"), (123, "sched_getaffinity"), (124, "sched_yield"),
    (125, "sched_get_priority_max"), (126, "sched_get_priority_min"), (127, "sched_rr_get_interval"), (128, "restart_syscall"), (129, "kill"),
    (130, "tkill"), (131, "tgkill"), (132, "sigaltstack"), (133, "rt_sigsuspend"), (134, "rt_sigaction"),
    (135, "rt_sigprocmask"), (136, "rt_sigpending"), (137, "rt_sigtimedwait"), (138, "rt_sigqueueinfo"), (139, "rt_sigreturn"),
    (140, "setpriority"), (141, "getpriority"), (142, "reboot"), (143, "setregid"), (144, "setgid"),
    (145, "setreuid"), (146, "setuid"), (147, "setresuid"), (148, "getresuid"), (149, "setresgid"),
    (150, "getresgid"), (151, "setfsuid"), (152, "setfsgid"), (153, "times"), (154, "setpgid"),
    (155, "getpgid"), (156, "getsid"), (157, "setsid"), (158, "getgroups"), (159, "setgroups"),
    (160, "uname"), (161, "sethostname"), (162, "setdomainname"), (163, "getrlimit"), (164, "setrlimit"),
    (165, "getrusage"), (166, "umask"), (167, "prctl"), (168, "getcpu"), (169, "gettimeofday"),
    (170, "settimeofday"), (171, "adjtimex"), (172, "getpid"), (173, "getppid"), (174, "getuid"),
    (175, "geteuid"), (176, "getgid"), (177, "getegid"), (178, "gettid"), (179, "sysinfo"),
    (180, "mq_open"), (181, "mq_unlink"), (182, "mq_timedsend"), (183, "mq_timedreceive"), (184, "mq_notify"),
    (185, "mq_getsetattr"), (186, "msgget"), (187, "msgctl"), (188, "msgrcv"), (189, "msgsnd"),
    (190, "semget"), (191, "semctl"), (192, "semtimedop"), (193, "semop"), (194, "shmget"),
    (195, "shmctl"), (196, "shmat"), (197, "shmdt"), (198, "socket"), (199, "socketpair"),
    (200, "bind"), (201, "listen"), (202, "accept"), (203, "connect"), (204, "getsockname"),
    (205, "getpeername"), (206, "sendto"), (207, "recvfrom"), (208, "setsockopt"), (209, "getsockopt"),
    (210, "shutdown"), (211, "sendmsg"), (212, "recvmsg"), (213, "readahead"), (214, "brk"),
    (215, "munmap"), (216, "mremap"), (217, "add_key"), (218, "request_key"), (219, "keyctl"),
    (220, "clone"), (221, "execve"), (222, "mmap"), (223, "fadvise64"), (224, "swapon"),
    (225, "swapoff"), (226, "mprotect"), (227, "msync"), (228, "mlock"), (229, "munlock"),
    (230, "mlockall"), (231, "munlockall"), (232, "mincore"), (233, "madvise"), (234, "remap_file_pages"),
    (235, "mbind"), (236, "get_mempolicy"), (237, "set_mempolicy"), (238, "migrate_pages"), (239, "move_pages"),
    (240, "rt_tgsigqueueinfo"), (241, "perf_event_open"), (242, "accept4"), (243, "recvmmsg"), (244, "arch_specific_syscall"),
    (260, "wait4"), (261, "prlimit64"), (262, "fanotify_init"), (263, "fanotify_mark"), (264, "name_to_handle_at"),
    (265, "open_by_handle_at"), (266, "clock_adjtime"), (267, "syncfs"), (268, "setns"), (269, "sendmmsg"),
    (270, "process_vm_readv"), (271, "process_vm_writev"), (272, "kcmp"), (273, "finit_module"), (274, "sched_setattr"),
    (275, "sched_getattr"), (276, "renameat2"), (277, "seccomp"), (278, "getrandom"), (279, "memfd_create"),
    (280, "bpf"), (281, "execveat"), (282, "userfaultfd"), (283, "membarrier"), (284, "mlock2"),
    (285, "copy_file_range"), (286, "preadv2"), (287, "pwritev2"), (288, "pkey_mprotect"), (289, "pkey_alloc"),
    (290, "pkey_free"), (291, "statx"), (292, "io_pgetevents"), (293, "rseq"), (294, "kexec_file_load"),
    (403, "clock_gettime64"), (404, "clock_settime64"), (405, "clock_adjtime64"), (406, "clock_getres_time64"), (407, "clock_nanosleep_time64"),
    (408, "timer_gettime64"), (409, "timer_settime64"), (410, "timerfd_gettime64"), (411, "timerfd_settime64"), (412, "utimensat_time64"),
    (413, "pselect6_time64"), (414, "ppoll_time64"), (416, "io_pgetevents_time64"), (417, "recvmmsg_time64"), (418, "mq_timedsend_time64"),
    (419, "mq_timedreceive_time64"), (420, "semtimedop_time64"), (421, "rt_sigtimedwait_time64"), (422, "futex_time64"), (423, "sched_rr_get_interval_time64"),
    (424, "pidfd_send_signal"), (425, "io_uring_setup"), (426, "io_uring_enter"), (427, "io_uring_register"), (428, "open_tree"),
    (429, "move_mount"), (430, "fsopen"), (431, "fsconfig"), (432, "fsmount"), (433, "fspick"),
    (434, "pidfd_open"), (435, "clone3"), (436, "close_range"), (437, "openat2"), (438, "pidfd_getfd"),
    (439, "faccessat2"), (440, "process_madvise"), (441, "epoll_pwait2"), (442, "mount_setattr"), (443, "quotactl_fd"),
    (444, "landlock_create_ruleset"), (445, "landlock_add_rule"), (446, "landlock_restrict_self"), (447, "memfd_secret"), (448, "process_mrelease"),
    (449, "futex_waitv"), (450, "set_mempolicy_home_node"), (451, "cachestat"), (452, "fchmodat2"), (453, "map_shadow_stack"),
    (454, "futex_wake"), (455, "futex_wait"), (456, "futex_requeue"), (457, "statmount"), (458, "listmount"),
    (459, "lsm_get_self_attr"), (460, "lsm_set_self_attr"), (461, "lsm_list_modules"), (462, "mseal"), (463, "setxattrat"),
    (464, "getxattrat"), (465, "listxattrat"), (466, "removexattrat"), (467, "open_tree_attr"), (468, "file_getattr"),
    (469, "file_setattr"), (470, "listns"), (471, "rseq_slice_yield"), (472, "syscalls"),
];

#[cfg(test)]
mod tests {
    use super::*;

    const X86_OBJDUMP: &str = "\
/tmp/firecracker:     file format elf64-x86-64

Disassembly of section .text:

<read_epoll>:
push   %rbp
mov    $0x0,%eax
syscall
ret

<write_epoll>:
mov    $0x1,%eax
mov    $0x1,%edi
syscall
ret

<call_write>:
mov    $0x1,%edi
mov    $0x2,%esi
call   <syscall>
ret

<tail_target>:
mov    $0x10,%eax
jmp    <read_epoll>
ret
";

    const AARCH64_OBJDUMP: &str = "\
/tmp/firecracker:     file format elf64-aarch64

Disassembly of section .text:

<sys_ioctl>:
mov    x8, #0x1d
svc    #0x0
ret

<sys_offset>:
mov    x0, #0x1
add    x0, x0, #0x3
mov    x8, #0x40
svc    #0x0

<sys_movk>:
mov    x0, #0x1
movk   x0, #0x8, lsl #16
mov    x8, #0x3f
svc    #0x0

<svc_with_comment>:
svc    #0x0 // syscall
";

    fn x86() -> Architecture {
        Architecture::X86_64
    }

    fn arm() -> Architecture {
        Architecture::Aarch64
    }

    #[test]
    fn parses_x86_instructions() {
        let insn = Instruction::parse("mov    $0x1,%eax", x86());
        assert_eq!(insn.mnemonic(), "mov");
        assert_eq!(insn.args(), ["$0x1", "%eax"]);
        assert_eq!(insn.text(), "mov $0x1,%eax");
        assert!(!insn.is_call());
        assert!(!insn.is_syscall());

        let insn = Instruction::parse("syscall", x86());
        assert!(insn.is_syscall());
        assert!(insn.args().is_empty());

        assert!(Instruction::parse("call   <syscall>", x86()).is_call());
        assert!(Instruction::parse("jmp    <main>", x86()).is_call());
        assert!(!Instruction::parse("ret", x86()).is_call());
    }

    #[test]
    fn parses_x86_comments() {
        let insn = Instruction::parse("mov    $0x0,%eax # zero the nr", x86());
        assert_eq!(insn.args(), ["$0x0", "%eax"]);
    }

    #[test]
    fn parses_aarch64_instructions() {
        let insn = Instruction::parse("add    x1, x1, #0x3", arm());
        assert_eq!(insn.mnemonic(), "add");
        assert_eq!(insn.args(), ["x1", "x1", "#0x3"]);
        assert!(!insn.is_call());

        assert!(Instruction::parse("bl     <syscall>", arm()).is_call());
        assert!(Instruction::parse("b      <main>", arm()).is_call());

        assert!(Instruction::parse("svc    #0x0", arm()).is_syscall());
        // `svc #0x1` is a different trap and not a syscall.
        assert!(!Instruction::parse("svc    #0x1", arm()).is_syscall());
        // Comments use `//` on this architecture.
        assert!(Instruction::parse("svc    #0x0 // trap", arm()).is_syscall());
    }

    #[test]
    fn x86_backpropagates_immediates_and_registers() {
        let insn = Instruction::parse("mov    $0x1,%eax", x86());
        assert_eq!(
            insn.backpropagate_register("%eax"),
            Ok(RegValue::Immediate(1))
        );
        // Unrelated registers are left untouched.
        assert_eq!(
            insn.backpropagate_register("%rsi"),
            Ok(RegValue::Register("%rsi".to_string()))
        );

        let insn = Instruction::parse("mov    %edi,%eax", x86());
        assert_eq!(
            insn.backpropagate_register("%eax"),
            Ok(RegValue::Register("%edi".to_string()))
        );

        let insn = Instruction::parse("xor    %eax,%eax", x86());
        assert_eq!(
            insn.backpropagate_register("%eax"),
            Ok(RegValue::Immediate(0))
        );

        let insn = Instruction::parse("push   %rbp", x86());
        assert_eq!(
            insn.backpropagate_register("%rbp"),
            Ok(RegValue::Register("%rbp".to_string()))
        );
        assert_eq!(
            insn.backpropagate_register("%rbx"),
            Ok(RegValue::Register("%rbx".to_string()))
        );
    }

    #[test]
    fn x86_backpropagation_fails_for_unsupported_instructions() {
        let insn = Instruction::parse("pop    %rax", x86());
        let err = insn.backpropagate_register("%rax").unwrap_err();
        assert!(matches!(err, BackpropError::UnsupportedInstruction { .. }));
        assert!(err.to_string().contains("%rax"));
        assert!(err.to_string().contains("pop"));
    }

    #[test]
    fn aarch64_backpropagates_through_transforms() {
        let insn = Instruction::parse("add    x1, x1, #0x4", arm());
        assert_eq!(
            insn.backpropagate_register("x1"),
            Ok(RegValue::Transformed {
                register: "x1".to_string(),
                transform: Transform::Add(4),
            })
        );
        let insn = Instruction::parse("sub    x1, x2, #0x4", arm());
        assert_eq!(
            insn.backpropagate_register("x1"),
            Ok(RegValue::Transformed {
                register: "x2".to_string(),
                transform: Transform::Sub(4),
            })
        );
        let insn = Instruction::parse("movk   x1, #0x8, lsl #16", arm());
        assert_eq!(
            insn.backpropagate_register("x1"),
            Ok(RegValue::Transformed {
                register: "x1".to_string(),
                transform: Transform::Movk {
                    immediate: 8,
                    shift: 16,
                },
            })
        );
        let insn = Instruction::parse("mov    x1, xzr", arm());
        assert_eq!(
            insn.backpropagate_register("x1"),
            Ok(RegValue::Immediate(0))
        );
    }

    #[test]
    fn transform_apply_semantics() {
        assert_eq!(Transform::Add(4).apply(0x100), 0x104);
        assert_eq!(Transform::Sub(0x10).apply(0x100), 0xf0);
        assert_eq!(
            Transform::Movk {
                immediate: 0x8,
                shift: 16,
            }
            .apply(0x1),
            0x80001
        );
        assert_eq!(
            Transform::Movk {
                immediate: 0xffff,
                shift: 48,
            }
            .apply(0),
            0xffff_i64.wrapping_shl(48)
        );
    }

    #[test]
    fn determine_register_value_walks_backwards() {
        let instructions = [
            Instruction::parse("mov    x1, #0x1", arm()),
            Instruction::parse("add    x1, x1, #0x3", arm()),
        ];
        assert_eq!(arm().determine_register_value(&instructions, "x1"), Ok(4));

        let instructions = [
            Instruction::parse("mov    x1, #0x1", arm()),
            Instruction::parse("movk   x1, #0x8, lsl #16", arm()),
        ];
        assert_eq!(
            arm().determine_register_value(&instructions, "x1"),
            Ok(0x80001)
        );

        let instructions = [Instruction::parse("mov    x1, #0x1", arm())];
        assert_eq!(arm().determine_register_value(&instructions, "x1"), Ok(1));
    }

    #[test]
    fn determine_register_value_reports_unresolved() {
        let instructions = [Instruction::parse("mov    $0x1,%eax", x86())];
        let err = x86()
            .determine_register_value(&instructions, "%rsi")
            .unwrap_err();
        assert!(matches!(err, BackpropError::ReachedStartOfFn { .. }));

        let instructions = [Instruction::parse("pop    %rax", x86())];
        let err = x86()
            .determine_register_value(&instructions, "%rax")
            .unwrap_err();
        assert!(matches!(err, BackpropError::UnsupportedInstruction { .. }));
    }

    #[test]
    fn generalize_reg_covers_partial_aliases() {
        assert_eq!(
            x86().generalize_reg("%rdi"),
            ["%rdi".to_string(), "%edi".to_string(), "%di".to_string()]
        );
        assert_eq!(
            x86().generalize_reg("%r10"),
            ["%r10".to_string(), "%r10d".to_string(), "%r10w".to_string()]
        );
        assert_eq!(x86().generalize_reg("%rbx"), ["%rbx", "%ebx", "%bx"]);
        assert_eq!(arm().generalize_reg("w3"), ["x3", "w3"]);
        assert_eq!(arm().generalize_reg("x12"), ["x12", "w12"]);
        assert_eq!(arm().generalize_reg("sp"), ["sp"]);
    }

    #[test]
    fn parses_objdump_into_functions() {
        let functions = parse_objdump_output(X86_OBJDUMP, x86());
        let names: Vec<&str> = functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["read_epoll", "write_epoll", "call_write", "tail_target"]
        );
        assert_eq!(functions[0].instructions.len(), 4);
        assert_eq!(functions[0].instructions[1].mnemonic(), "mov");
        assert!(functions[0].instructions[2].is_syscall());
    }

    #[test]
    fn finds_syscalls_behind_syscall_instructions() {
        let functions = parse_objdump_output(X86_OBJDUMP, x86());
        let found = find_syscalls_in_functions(&functions, x86());

        // read_epoll: `push %rbp` must not prevent resolving %eax.
        assert_eq!(found["read"][0], vec![None; 6]);
        // write_epoll: %eax = 1 and %rdi = 1.
        assert_eq!(found["write"][0][0], Some(1));
        assert!(found["write"][0][1..].iter().all(Option::is_none));
    }

    #[test]
    fn finds_syscalls_behind_call_wrappers() {
        let functions = parse_objdump_output(X86_OBJDUMP, x86());
        let found = find_syscalls_in_functions(&functions, x86());

        // `call <syscall>` passes the syscall number as the first argument, so
        // `call_write` reports %rsi = 2 and unknown remaining arguments.
        let write_calls = &found["write"];
        assert_eq!(write_calls.len(), 2);
        assert_eq!(write_calls[1], vec![Some(2), None, None, None, None]);
        // tail_target jumps into read_epoll instead of issuing a syscall.
        assert_eq!(found["read"].len(), 1);
    }

    #[test]
    fn resolves_syscall_names_per_arch() {
        assert_eq!(x86().resolve_syscall(0), Some("read"));
        assert_eq!(x86().resolve_syscall(1), Some("write"));
        assert_eq!(x86().resolve_syscall(16), Some("ioctl"));
        assert_eq!(x86().resolve_syscall(-1), None);

        assert_eq!(arm().resolve_syscall(63), Some("read"));
        assert_eq!(arm().resolve_syscall(64), Some("write"));
        assert_eq!(arm().resolve_syscall(29), Some("ioctl"));
        assert_eq!(arm().resolve_syscall(222), Some("mmap"));
        assert_eq!(arm().resolve_syscall(9999), None);

        assert_eq!(x86().resolve_syscall_number("write"), Some(1));
        assert_eq!(arm().resolve_syscall_number("mmap"), Some(222));
        assert_eq!(arm().resolve_syscall_number("no_such_syscall"), None);
        assert_eq!(Architecture::from_name("aarch64"), Some(arm()));
        assert_eq!(Architecture::from_name("riscv64"), None);
    }

    #[test]
    fn finds_aarch64_syscalls_with_transforms() {
        let functions = parse_objdump_output(AARCH64_OBJDUMP, arm());
        let found = find_syscalls_in_functions(&functions, arm());

        // ioctl, with all arguments unknown.
        assert_eq!(found["ioctl"].len(), 1);
        assert_eq!(found["ioctl"][0].len(), 8);
        assert!(found["ioctl"][0].iter().all(Option::is_none));

        // `movk` reassembles 0x80001 in x0 before the syscall.
        assert_eq!(found["read"][0][0], Some(0x80001));
        // `add` forward-propagates x0 = 1 into 4.
        assert_eq!(found["write"][0][0], Some(4));
    }

    #[test]
    fn skips_syscall_wrapper_functions() {
        let output = "\
/tmp/firecracker:     file format elf64-x86-64

Disassembly of section .text:

<syscall>:
mov    $0x1,%eax
syscall
ret
";
        let functions = parse_objdump_output(output, x86());
        assert!(is_syscall_wrapper("syscall"));
        assert!(is_syscall_wrapper("tcsetattr"));
        assert!(!is_syscall_wrapper("main"));
        assert!(find_syscalls_in_functions(&functions, x86()).is_empty());
    }

    #[test]
    fn specific_wrappers_are_described() {
        let mmap = specific_syscall_wrapper("__mmap").expect("mmap wrapper exists");
        assert_eq!(mmap.syscall, "mmap");
        assert_eq!(mmap.nargs, 6);
        let tcsetattr = specific_syscall_wrapper("tcsetattr").expect("tcsetattr wrapper exists");
        assert_eq!(tcsetattr.syscall, "ioctl");
        assert_eq!(tcsetattr.arg_transform, [(1, Transform::Add(0x5402))]);
        assert!(specific_syscall_wrapper("main").is_none());
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fc-static-analysis-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir is created");
        dir
    }

    fn write_seccomp_fixture(dir: &Path) -> PathBuf {
        let path = dir.join("seccomp.json");
        let fixture = serde_json::json!({
            "vmm": {
                "filter": [
                    {"syscall": "read"},
                    {"syscall": "restart_syscall"},
                    {
                        "syscall": "fallocate",
                        "args": [
                            {"index": 1, "type": "dword", "op": "eq", "val": 3}
                        ]
                    }
                ]
            },
            "api": {
                "filter": [
                    {
                        "syscall": "fcntl",
                        "args": [
                            {"index": 1, "type": "dword", "op": "eq", "val": 2},
                            {"index": 2, "type": "dword", "op": "eq", "val": 1}
                        ]
                    }
                ]
            },
            "vcpu": {
                "filter": [
                    {
                        "syscall": "ioctl",
                        "args": [{
                            "index": 1,
                            "type": "qword",
                            "op": {"masked_eq": 18446744073709551613_u64},
                            "val": 2199023255552_u64
                        }]
                    }
                ]
            }
        });
        std::fs::write(&path, fixture.to_string()).expect("fixture is written");
        path
    }

    #[test]
    fn loads_seccomp_rules() {
        let dir = temp_dir("load");
        let path = write_seccomp_fixture(&dir);
        let rules = load_seccomp_rules(&path).expect("fixture parses");

        assert_eq!(rules["read"], vec![RuleArgs::new()]);
        assert_eq!(
            rules["fallocate"],
            vec![RuleArgs::from([(1, ArgConstraint { val: 3, mask: None })])]
        );
        assert_eq!(rules["fcntl"][0].len(), 2);
        let masked = &rules["ioctl"][0][&1];
        assert_eq!(masked.val, 2199023255552);
        assert_eq!(masked.mask, Some(18446744073709551613));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn seccomp_loader_rejects_unknown_ops() {
        let dir = temp_dir("bad-op");
        let path = dir.join("seccomp.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "vmm": {"filter": [{
                    "syscall": "foo",
                    "args": [{"index": 0, "op": "ge", "val": 1}]
                }]},
                "api": {"filter": []},
                "vcpu": {"filter": []}
            })
            .to_string(),
        )
        .expect("written");
        let err = load_seccomp_rules(&path).unwrap_err();
        assert!(err.to_string().contains("Unknown seccomp op"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn arg_matches_handles_masks() {
        assert!(arg_matches(3, 3, None));
        assert!(!arg_matches(4, 3, None));
        assert!(arg_matches(0x2000_0000, 0x2000_0000, Some(0xffff_ffff)));
        // Bits outside the mask are ignored, so this still matches.
        assert!(arg_matches(0x2000_0001, 0x2000_0000, Some(0xffff_0000)));
        assert!(!arg_matches(0x2001_0000, 0x2000_0000, Some(0xffff_0000)));
        // Values are compared in two's complement, as the kernel sees them.
        assert!(arg_matches(-1, u64::MAX, Some(u64::MAX)));
        assert!(arg_matches(-1, u32::MAX as u64, Some(u32::MAX as u64)));
        assert!(!arg_matches(-1, u32::MAX as u64, Some(u64::MAX)));
    }

    #[test]
    fn unneeded_rules_reports_unused_and_unmatched_rules() {
        let dir = temp_dir("unneeded");
        let path = write_seccomp_fixture(&dir);
        let rules = load_seccomp_rules(&path).expect("fixture parses");

        let mut found: SyscallInvocations = BTreeMap::new();
        // read with all arguments unknown.
        found.insert("read".to_string(), vec![vec![None; 6]]);
        // fallocate always called with a different mode than the rule allows.
        found.insert("fallocate".to_string(), vec![vec![None, Some(1)]]);
        // One of the two fcntl calls matches both constraints, so the rule is
        // needed.
        found.insert(
            "fcntl".to_string(),
            vec![vec![None, Some(2), Some(1)], vec![None, Some(3), Some(1)]],
        );
        // ioctl is never called, so its masked rule is redundant.

        let redundant = determine_unneeded_seccomp_rules(&rules, &found);
        let names: Vec<&str> = redundant.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, vec!["fallocate", "ioctl"]);
        // read allows all arguments, so it can never be reported.
        assert!(!names.contains(&"read"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unneeded_rules_reports_rules_no_invocation_satisfies() {
        let mut rules = SeccompAllowlist::new();
        rules.insert(
            "fcntl".to_string(),
            vec![RuleArgs::from([
                (1, ArgConstraint { val: 2, mask: None }),
                (2, ArgConstraint { val: 1, mask: None }),
            ])],
        );
        let mut found = SyscallInvocations::new();
        // No single invocation satisfies all constraints of the rule.
        found.insert(
            "fcntl".to_string(),
            vec![vec![None, Some(2), Some(0)], vec![None, Some(3), Some(1)]],
        );
        let redundant = determine_unneeded_seccomp_rules(&rules, &found);
        assert_eq!(redundant.len(), 1);
        assert_eq!(redundant[0].0, "fcntl");
    }

    #[test]
    fn unneeded_rules_keeps_unconstrained_rules_of_used_syscalls() {
        let mut rules = SeccompAllowlist::new();
        rules.insert("write".to_string(), vec![RuleArgs::new()]);
        let mut found = SyscallInvocations::new();
        found.insert("write".to_string(), vec![vec![Some(1), Some(2)]]);

        assert!(determine_unneeded_seccomp_rules(&rules, &found).is_empty());
    }

    #[test]
    fn unneeded_rules_reports_syscalls_without_invocations() {
        let mut rules = SeccompAllowlist::new();
        rules.insert(
            "read".to_string(),
            vec![
                RuleArgs::new(),
                RuleArgs::from([(0, ArgConstraint { val: 1, mask: None })]),
            ],
        );
        let mut found = SyscallInvocations::new();
        // With no invocation at all the universal quantification holds
        // vacuously, so every rule of the syscall is reported.
        found.insert("read".to_string(), Vec::new());

        let redundant = determine_unneeded_seccomp_rules(&rules, &found);
        assert_eq!(redundant.len(), 2);
        assert!(redundant.iter().all(|(name, _)| name == "read"));
    }

    #[test]
    fn unneeded_rules_keeps_rules_with_unknown_arguments() {
        let mut rules = SeccompAllowlist::new();
        rules.insert(
            "fallocate".to_string(),
            vec![RuleArgs::from([(1, ArgConstraint { val: 3, mask: None })])],
        );
        let mut found = SyscallInvocations::new();
        // Unknown argument values cannot prove the rule unnecessary.
        found.insert("fallocate".to_string(), vec![vec![None, None]]);
        assert!(determine_unneeded_seccomp_rules(&rules, &found).is_empty());
    }

    #[test]
    fn known_superfluous_rules_only_contains_restart_syscall() {
        let rules = known_superfluous_rules();
        assert_eq!(rules.len(), 1);
        assert!(rules["restart_syscall"][0].is_empty());
    }

    #[test]
    fn host_seccomp_path_matches_architecture() {
        let path = host_seccomp_json_path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert_eq!(
            name,
            format!("{}-unknown-linux-musl.json", defs::host_arch())
        );
        assert!(load_host_seccomp_rules().is_ok());
    }
}
