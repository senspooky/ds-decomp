use unarm::{
    Ins, ParsedIns,
    args::{Argument as Arg, OffsetReg, Reg, Register},
};

/// Detects illegal code sequences that never appears in any game.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum IllegalCodeState {
    #[default]
    Start,
    ShiftedRegisterValue {
        reg: Register,
    },
    Illegal {
        reason: &'static str,
    },
}

impl IllegalCodeState {
    pub fn handle(self, ins: Ins, parsed_ins: &ParsedIns) -> Self {
        if ins.is_illegal() || parsed_ins.is_illegal() {
            return Self::Illegal { reason: "illegal opcode" };
        }

        if matches!(ins, Ins::Thumb(_))
            && parsed_ins.mnemonic == "lsl"
            && let Arg::Reg(Reg { reg: Register::R0, .. }) = parsed_ins.args[0]
            && let Arg::Reg(Reg { reg: Register::R0, .. }) = parsed_ins.args[1]
            && let Arg::UImm(0) = parsed_ins.args[2]
        {
            // In Thumb with divided syntax, 0000 disassembles into lsl r0, r0, #0x0 and is a no-op
            return Self::Illegal { reason: "Thumb no-op 'lsl r0, r0, #0' or 0000 in hex" };
        }

        let args = &parsed_ins.args;
        match (self, ins.mnemonic(), args[0], args[1], args[2]) {
            // Find registers with shifted value
            (_, "lsl", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "lsls", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "lsr", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "lsrs", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "asr", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "asrs", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "ror", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "rors", Arg::Reg(Reg { reg, .. }), _, _) => Self::ShiftedRegisterValue { reg },

            // Dereferencing shifted registers
            (
                Self::ShiftedRegisterValue { reg },
                "stm" | "stmia",
                Arg::Reg(Reg { reg: base, .. }),
                _,
                _,
            ) if reg == base => Self::Illegal { reason: "dereferencing shifted registers" },

            // Dereferencing registers offset by the same register
            (
                _,
                "str",
                _,
                Arg::Reg(Reg { deref: true, reg: base, .. }),
                Arg::OffsetReg(OffsetReg { reg: offset, .. }),
            ) if base == offset => {
                Self::Illegal { reason: "dereferencing registers offset by itself" }
            }

            // Reading from PC into PC
            (_, "ldm", Arg::Reg(Reg { reg: Register::Pc, .. }), Arg::RegList(reg_list), _)
                if reg_list.contains(Register::Pc) =>
            {
                Self::Illegal { reason: "reading from PC into PC" }
            }

            _ => Self::default(),
        }
    }
}

pub const ILLEGAL_CODE_PATTERNS: &[&[u8]] = &[&[0x00, 0x02, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00]];
