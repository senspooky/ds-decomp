use std::io;

use anyhow::{Result, bail};
use ds_decomp::{
    analysis::{
        functions::Function,
        jump_table::{JumpTableKind, ThumbJumpTableJump, ThumbJumpTableKind},
    },
    config::symbol::SymJumpTable,
};
use unarm::{ArmVersion, DisplayOptions, Endian, ParseFlags, ParseMode, Parser, RegNames};

use crate::{
    config::symbol::{SymDataExt, SymbolLookup},
    util::bytes::FromSlice,
};

pub trait FunctionExt {
    fn write_assembly<W: io::Write>(
        &self,
        w: &mut W,
        symbols: &SymbolLookup,
        module_code: &[u8],
        base_address: u32,
        ual: bool,
    ) -> Result<()>;
}

impl FunctionExt for Function {
    fn write_assembly<W: io::Write>(
        &self,
        w: &mut W,
        symbols: &SymbolLookup,
        module_code: &[u8],
        base_address: u32,
        ual: bool,
    ) -> Result<()> {
        let mode = if self.is_thumb() { ParseMode::Thumb } else { ParseMode::Arm };
        let mut parser = Parser::new(
            mode,
            self.start_address(),
            Endian::Little,
            ParseFlags { ual, version: ArmVersion::V5Te },
            self.code(module_code, base_address),
        );

        if self.start_address() < self.first_instruction_address() {
            parser.mode = ParseMode::Data;
        }

        let mut jump_table = None;

        while let Some((address, ins, parsed_ins)) = parser.next() {
            if address == self.first_instruction_address() {
                // declare self
                writeln!(w, "    .global {}", self.name())?;
                if self.is_thumb() {
                    writeln!(w, "    thumb_func_start {}", self.name())?;
                } else {
                    writeln!(w, "    arm_func_start {}", self.name())?;
                }
                writeln!(w, "{}: ; {:#010x}", self.name(), self.first_instruction_address())?;
            }

            // How far the parser actually advanced, which is the only thing that knows a Thumb
            // `bl`/`blx` pair is four bytes -- `ParseMode::Thumb.instruction_size` always answers
            // two. Getting this wrong moves the address the constant pool is looked for at, and a
            // pool that starts directly after a Thumb `bl` is then disassembled as code with no
            // label on it, leaving the `ldr` that loads it pointing at nothing.
            let mut ins_size = parser.address - address;

            // write label
            if let Some(label) = symbols.symbol_map.get_label(address)? {
                writeln!(w, "{}:", label.name)?;
            }
            if let Some((table, sym)) = symbols.symbol_map.get_jump_table(address)? {
                jump_table = Some((table, sym));
                writeln!(w, "{}: ; jump table", sym.name)?;
            }

            'ins: {
                // A constant pool the function's own code sits after is emitted by the scan at the
                // bottom of this loop, which starts from the instruction just written. A function
                // whose start was moved back onto a pool ahead of its code has no such instruction
                // for its first constant, so that one has to be written here or it comes out as a
                // `.word #0x...` pseudo-instruction with no label on it -- as the SHA-1 round
                // constant at 0x02077cd4 in ARM9 main did.
                if let Some(pool_symbol) = symbols.symbol_map.get_pool_constant(address)?
                    && self.pool_constants().contains_key(&address)
                {
                    let start = (address - base_address) as usize;
                    let const_value = u32::from_le_slice(&module_code[start..]);
                    write!(w, "{}: ", pool_symbol.name)?;
                    if !symbols.write_symbol(w, address, const_value, &mut false, "")? {
                        writeln!(w, ".word {const_value:#x}")?;
                    }
                    ins_size = 4;
                    break 'ins;
                }

                // write data
                if let Some((data, sym)) = symbols.symbol_map.get_data(address)? {
                    let Some(size) = data.size() else {
                        log::error!("Inline tables must have a known size");
                        bail!("Inline tables must have a known size");
                    };
                    parser.seek_forward(address + size);

                    writeln!(w, "{}: ; inline table", sym.name)?;

                    let start = (sym.addr - base_address) as usize;
                    let end = start + size as usize;
                    let bytes = &module_code[start..end];
                    data.write_assembly(w, sym, bytes, symbols)?;
                    ins_size = size;
                    break 'ins;
                }

                // possibly terminate jump table
                if jump_table.is_some_and(|(table, sym)| address >= sym.addr + table.size) {
                    jump_table = None;
                }

                // A `load` relocation applies to a data word, never to an instruction. If one
                // turns up where an instruction was expected, the word is data which no instruction
                // in the function loads, so it was never found as a pool constant. DS Protect
                // leaves such data in the constant pool of the functions it protects.
                let data_word = jump_table.is_none()
                    && parser.mode != ParseMode::Data
                    && symbols.has_data_relocation(address);
                if data_word {
                    ins_size = 4;
                }

                // write instruction
                match jump_table {
                    Some((SymJumpTable { kind: JumpTableKind::Thumb { kind, jump }, .. }, sym)) => {
                        match kind {
                            ThumbJumpTableKind::Halfword => {
                                let value = i32::from(ins.code() as i16);
                                write_numerical_jump_table_entry(
                                    w, symbols, sym, value, ".short", address, jump,
                                )?;
                            }
                            ThumbJumpTableKind::Byte => {
                                let code = ins.code() as i16;
                                let [first_value, second_value] = code.to_le_bytes();
                                let first_value = first_value as i8 as i32;
                                let second_value = second_value as i8 as i32;
                                write_numerical_jump_table_entry(
                                    w,
                                    symbols,
                                    sym,
                                    first_value,
                                    ".byte",
                                    address,
                                    jump,
                                )?;
                                write_jump_table_case(w, jump_table, 1, address)?;
                                write_numerical_jump_table_entry(
                                    w,
                                    symbols,
                                    sym,
                                    second_value,
                                    ".byte",
                                    address + 1,
                                    jump,
                                )?;
                                write_jump_table_case(w, jump_table, 1, address + 1)?;
                            }
                        }
                    }
                    _ if data_word => {
                        let start = (address - base_address) as usize;
                        let value = u32::from_le_slice(&module_code[start..]);
                        if !symbols.write_symbol(w, address, value, &mut false, "    ")? {
                            writeln!(w, "    .word {value:#x}")?;
                        }
                        parser.seek_forward(address + 4);
                    }
                    _ => {
                        if parser.mode != ParseMode::Data {
                            write!(w, "    ")?;
                        }
                        let pc_load_offset = if self.is_thumb() { 4 } else { 8 };
                        write!(
                            w,
                            "{}",
                            parsed_ins.display_with_symbols(
                                DisplayOptions {
                                    reg_names: RegNames { ip: true, ..Default::default() }
                                },
                                unarm::Symbols {
                                    lookup: symbols,
                                    program_counter: address,
                                    pc_load_offset
                                }
                            )
                        )?;
                        if let Some(reference) =
                            parsed_ins.pc_relative_reference(address, pc_load_offset)
                        {
                            symbols.write_ambiguous_symbols_comment(w, address, reference)?;
                        }
                        write_jump_table_case(w, jump_table, ins_size, address)?;
                    }
                }
            }

            // write pool constants
            let next_address = address + ins_size;
            for i in 0.. {
                let pool_address = next_address + i * 4;
                if self.pool_constants().contains_key(&pool_address) {
                    let start = pool_address - base_address;
                    let bytes = &module_code[start as usize..];
                    let const_value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

                    let Some(pool_symbol) = symbols.symbol_map.get_pool_constant(pool_address)?
                    else {
                        log::error!(
                            "Pool constant at {:#010x} in function {} has no symbol",
                            pool_address,
                            self.name()
                        );
                        bail!(
                            "Pool constant at {:#010x} in function {} has no symbol",
                            pool_address,
                            self.name()
                        );
                    };
                    write!(w, "{}: ", pool_symbol.name)?;

                    if !symbols.write_symbol(w, pool_address, const_value, &mut false, "")? {
                        writeln!(w, ".word {const_value:#x}")?;
                    }
                } else {
                    if pool_address > parser.address {
                        assert!(
                            pool_address <= self.end_address(),
                            "Failed to seek unarm parser to pool constant at {:#010x} for function at {:#010x}..{:#010x}",
                            pool_address,
                            self.start_address(),
                            self.end_address()
                        );
                        parser.seek_forward(pool_address);
                    }
                    if pool_address == self.first_instruction_address() {
                        // No more pre-code pool constants, start disassembling
                        parser.mode = mode;
                    }
                    break;
                }
            }
        }

        if self.is_thumb() {
            writeln!(w, "    thumb_func_end {}", self.name())?;
        } else {
            writeln!(w, "    arm_func_end {}", self.name())?;
        }

        writeln!(w)?;

        Ok(())
    }
}

fn write_jump_table_case<W: io::Write>(
    w: &mut W,
    jump_table: Option<(SymJumpTable, &ds_decomp::config::symbol::Symbol)>,
    ins_size: u32,
    address: u32,
) -> std::result::Result<(), io::Error> {
    if let Some((_table, sym)) = jump_table {
        let case = (address - sym.addr) / ins_size;
        writeln!(w, " ; case {case}")
    } else {
        writeln!(w)
    }
}

fn write_numerical_jump_table_entry<W: io::Write>(
    w: &mut W,
    symbols: &SymbolLookup<'_>,
    sym: &ds_decomp::config::symbol::Symbol,
    value: i32,
    directive: &str,
    address: u32,
    jump: ThumbJumpTableJump,
) -> Result<(), anyhow::Error> {
    let pc_offset = match jump {
        ThumbJumpTableJump::AddPc => 2,
        ThumbJumpTableJump::Bx => 0,
    };
    let label_address = (sym.addr.cast_signed() + value + pc_offset).cast_unsigned() & !1;
    let Some(label) = symbols.symbol_map.get_label(label_address)? else {
        log::error!(
            "Expected label for jump table destination from {address:#010x} to {label_address:#010x}"
        );
        bail!(
            "Expected label for jump table destination from {address:#010x} to {label_address:#010x}"
        );
    };
    writeln!(w, "    {} {} - {} {}", directive, label.name, sym.name, match jump {
        ThumbJumpTableJump::AddPc => "- 2",
        ThumbJumpTableJump::Bx => "+ 1",
    },)?;
    Ok(())
}
