use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use clap::Args;
use ds_decomp::{
    analysis::exception::{ExceptionData, ExceptionTableEntry},
    config::{
        config::Config,
        module::{FIND_EXCEPTION_TABLE_SYMBOL_NAME, ModuleKind},
        symbol::SymData,
    },
};
use ds_rom::rom::raw::AutoloadKind;

use crate::config::program::Program;

/// Locates link-time constants __exception_table_start/end__.
#[derive(Args, Clone)]
pub struct FindExceptix {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Dry run, do not write to any files.
    #[arg(long, short = 'd')]
    dry: bool,
}

impl FindExceptix {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let rom = config.load_rom(config_path)?;

        let mut program = Program::from_config(config_path, &config, &rom)?;

        let autoloads = rom.arm9().autoloads()?;
        let unknown_autoloads = autoloads
            .iter()
            .filter(|a| !matches!(a.kind(), AutoloadKind::Unknown(_)))
            .collect::<Vec<_>>();
        let Some(exception_data) = ExceptionData::analyze(rom.arm9(), &unknown_autoloads)? else {
            log::info!("{FIND_EXCEPTION_TABLE_SYMBOL_NAME} not found, no changes will be made");
            return Ok(());
        };

        let mut found = false;
        if self.fix_module(&mut program, ModuleKind::Arm9, &exception_data)? {
            found = true;
        } else {
            for autoload in unknown_autoloads {
                if self.fix_module(
                    &mut program,
                    ModuleKind::Autoload(autoload.kind()),
                    &exception_data,
                )? {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            bail!(
                "{FIND_EXCEPTION_TABLE_SYMBOL_NAME} found but it did not belong to ARM9 main or custom autoloads?"
            );
        }

        self.add_exception_table_symbols(&mut program, exception_data)?;

        if self.dry {
            log::info!("Dry run, not writing changes to files.");
            return Ok(());
        }

        program.write_to_files(config_path, &config)?;

        Ok(())
    }

    fn fix_module(
        &self,
        program: &mut Program,
        module_kind: ModuleKind,
        exception_data: &ExceptionData,
    ) -> Result<bool> {
        let (symbol_map, module) = program
            .symbol_map_and_module_mut(module_kind)
            .with_context(|| format!("Module not found: {module_kind}"))?;
        let function = module.analyze_find_exception_table_fn(
            exception_data.find_exception_table_fn_addr,
            exception_data.find_exception_table_fn,
            symbol_map,
        )?;
        if function.is_some() {
            log::info!(
                "{FIND_EXCEPTION_TABLE_SYMBOL_NAME} found in {module_kind}, adding link-time constant relocations"
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn add_exception_table_symbols(
        &self,
        program: &mut Program,
        exception_data: ExceptionData<'_>,
    ) -> Result<(), anyhow::Error> {
        let symbol_map = program.symbol_maps_mut().get_mut(ModuleKind::Arm9);
        let mut ex_symbols = 0;
        let mut et_symbols = 0;
        for (i, entry) in exception_data.exception_table.iter().enumerate() {
            let address = exception_data.exceptix_start
                + (i * std::mem::size_of::<ExceptionTableEntry>()) as u32;

            if let Some((id, symbol)) = symbol_map.by_address(address)? {
                if !symbol.name.starts_with("@EX@") {
                    symbol_map.remove(id);
                    symbol_map.add_data(
                        Some(format!("@EX@{:08x}", entry.function_address)),
                        address,
                        SymData::Word { count: Some(3) },
                    )?;
                }
            } else {
                symbol_map.add_data(
                    Some(format!("@EX@{:08x}", entry.function_address)),
                    address,
                    SymData::Word { count: Some(3) },
                )?;
            }
            ex_symbols += 1;

            if (entry.function_length & 1) == 0 {
                if let Some((id, symbol)) = symbol_map.by_address(entry.exception_record)? {
                    if !symbol.name.starts_with("@ET@") {
                        symbol_map.remove(id);
                        symbol_map.add_data(
                            Some(format!("@ET@{:08x}", entry.function_address)),
                            entry.exception_record,
                            SymData::Any,
                        )?;
                    }
                } else {
                    symbol_map.add_data(
                        Some(format!("@ET@{:08x}", entry.function_address)),
                        entry.exception_record,
                        SymData::Any,
                    )?;
                }
                et_symbols += 1;
            }
        }
        log::info!("Found {ex_symbols} exception table records in .exception");
        log::info!("Found {et_symbols} exception table entries in .exceptix");
        Ok(())
    }
}
