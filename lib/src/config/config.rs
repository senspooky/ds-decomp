use std::{
    backtrace::Backtrace,
    path::{Path, PathBuf},
};

use ds_rom::{
    crypto::dsprot,
    rom::{Rom, RomLoadOptions, RomSaveError, raw::AutoloadKind},
};
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::{
    config::{
        delinks::{Delinks, DelinksParseError},
        module::{Module, ModuleError, ModuleKind, ModuleOptions},
        relocations::{Relocations, RelocationsParseError},
        symbol::SymbolMaps,
    },
    rom::rom::{RomExt, RomGetCodeError},
    util::io::{FileError, open_file},
};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub rom_config: PathBuf,
    pub build_path: PathBuf,
    pub delinks_path: PathBuf,
    #[serde(skip_serializing_if = "is_false", default)]
    pub enable_dsprot: bool,
    pub main_module: ConfigModule,
    /// The DSi-exclusive ARM9i program, if this project models it. It is an extern module: dsd
    /// knows its symbols but does not disassemble, delink, build or check it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arm9i: Option<ConfigExternModule>,
    pub autoloads: Vec<ConfigAutoload>,
    pub overlays: Vec<ConfigOverlay>,
}

#[derive(Debug, Snafu)]
pub enum ConfigParseError {
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(display("Failed to parse dsd config file '{}': {error}\n{backtrace}", path.display()))]
    SerdeYml { path: PathBuf, error: Box<serde_saphyr::Error>, backtrace: Backtrace },
}

#[derive(Debug, Snafu)]
pub enum LoadModuleError {
    #[snafu(display("Failed to load module config for kind {module_kind}: \n{backtrace}"))]
    ModuleConfigNotFound { module_kind: ModuleKind, backtrace: Backtrace },
    #[snafu(transparent)]
    RelocationsParse { source: RelocationsParseError },
    #[snafu(transparent)]
    DelinksParse { source: DelinksParseError },
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(transparent)]
    Module { source: ModuleError },
    #[snafu(transparent)]
    RomGetCode { source: RomGetCodeError },
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Config, ConfigParseError> {
        let file = open_file(path)?;
        serde_saphyr::from_reader(file).map_err(|error| SerdeYmlSnafu { path, error }.build())
    }

    pub fn get_module_config_by_kind(&self, module_kind: ModuleKind) -> Option<&ConfigModule> {
        match module_kind {
            ModuleKind::Arm9 => Some(&self.main_module),
            // Extern modules have no built object, delinks or relocations.
            ModuleKind::Arm9i => None,
            ModuleKind::Autoload(autoload_kind) => self
                .autoloads
                .iter()
                .find(|autoload| autoload.kind == autoload_kind)
                .map(|autoload| &autoload.module),
            ModuleKind::Overlay(id) => {
                self.overlays.iter().find(|overlay| overlay.id == id).map(|overlay| &overlay.module)
            }
        }
    }

    pub fn get_module_config_by_kind_mut(
        &mut self,
        module_kind: ModuleKind,
    ) -> Option<&mut ConfigModule> {
        match module_kind {
            ModuleKind::Arm9 => Some(&mut self.main_module),
            ModuleKind::Arm9i => None,
            ModuleKind::Autoload(autoload_kind) => self
                .autoloads
                .iter_mut()
                .find(|autoload| autoload.kind == autoload_kind)
                .map(|autoload| &mut autoload.module),
            ModuleKind::Overlay(id) => self
                .overlays
                .iter_mut()
                .find(|overlay| overlay.id == id)
                .map(|overlay| &mut overlay.module),
        }
    }

    pub fn load_module<P: AsRef<Path>>(
        &self,
        config_path: P,
        symbol_maps: &mut SymbolMaps,
        module_kind: ModuleKind,
        rom: &Rom,
    ) -> Result<Module, LoadModuleError> {
        let config_path = config_path.as_ref();
        let symbol_map = symbol_maps.get_mut(module_kind);
        let module_config = self
            .get_module_config_by_kind(module_kind)
            .ok_or_else(|| ModuleConfigNotFoundSnafu { module_kind }.build())?;
        let relocations = Relocations::from_file(config_path.join(&module_config.relocations))?;
        let delinks = Delinks::from_file(config_path.join(&module_config.delinks), module_kind)?;
        let code = rom.get_code(module_kind)?;

        let module = Module::new(symbol_map, ModuleOptions {
            kind: module_kind,
            name: module_config.name.clone(),
            relocations,
            sections: delinks.sections,
            code: &code,
            signed: false,
        })?;

        Ok(module)
    }

    pub fn load_rom<P: AsRef<Path>>(&self, config_path: P) -> Result<Rom<'_>, RomSaveError> {
        let config_path = config_path.as_ref();
        let mut rom = Rom::load(config_path.join(&self.rom_config), RomLoadOptions {
            key: None,
            compress: false,
            encrypt: false,
            load_files: false,
            load_header: false,
            load_banner: false,
            load_multiboot_signature: false,
        })?;

        if !self.enable_dsprot {
            // DS Protect not enabled in this project yet, revert ROM output to what it was before
            // dsd 0.12.0
            let encrypt_options = &dsprot::DsProtEncryptOptions { encode_relocations: false };
            rom.arm9_mut().encrypt_dsprot(encrypt_options)?;
            for overlay in rom.arm9_overlays_mut() {
                overlay.encrypt_dsprot(encrypt_options)?;
            }
        }

        Ok(rom)
    }

    /// Iterates the extern modules: those dsd only knows the symbols of. They are not part of
    /// [`Self::iter_modules`], which yields the modules that get disassembled, delinked and built.
    pub fn iter_extern_modules(&self) -> impl Iterator<Item = (ModuleKind, &ConfigExternModule)> {
        self.arm9i.iter().map(|arm9i| (ModuleKind::Arm9i, arm9i))
    }

    pub fn get_extern_module_by_kind(
        &self,
        module_kind: ModuleKind,
    ) -> Option<&ConfigExternModule> {
        match module_kind {
            ModuleKind::Arm9i => self.arm9i.as_ref(),
            _ => None,
        }
    }

    pub fn iter_modules(&self) -> impl Iterator<Item = (ModuleKind, &ConfigModule)> {
        std::iter::once((ModuleKind::Arm9, &self.main_module))
            .chain(self.autoloads.iter().map(|a| (ModuleKind::Autoload(a.kind), &a.module)))
            .chain(self.overlays.iter().map(|o| (ModuleKind::Overlay(o.id), &o.module)))
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConfigModule {
    /// Name of module
    pub name: String,
    /// Binary file to build
    pub object: PathBuf,
    /// 64-bit fxhash of the binary file
    pub hash: String,
    /// Path to delinks file
    pub delinks: PathBuf,
    /// Path to symbols file
    pub symbols: PathBuf,
    /// Path to relocs file
    pub relocations: PathBuf,
}

/// A module that dsd does not build. Only its symbols are known, so that relocations from built
/// modules can name a destination inside it instead of emitting a bare address. `dsd lcf` gives
/// those symbols to the linker as absolute addresses.
///
/// This is what the DSi-exclusive ARM9i program is modelled as: it is a separate binary in the ROM,
/// loaded by the DSi boot ROM rather than by anything dsd links, and ARM9 main calls into it.
#[derive(Serialize, Deserialize)]
pub struct ConfigExternModule {
    /// Name of module.
    pub name: String,
    /// Address the module is loaded at.
    pub base_address: u32,
    /// Size of the module in bytes. Symbols outside this range are rejected.
    pub size: u32,
    /// Path to symbols file.
    pub symbols: PathBuf,
}

impl ConfigExternModule {
    pub fn end_address(&self) -> u32 {
        self.base_address + self.size
    }

    pub fn contains(&self, address: u32) -> bool {
        (self.base_address..self.end_address()).contains(&address)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConfigOverlay {
    pub id: u16,
    #[serde(default = "default_overlay_signed", skip_serializing_if = "skip_overlay_signed")]
    pub signed: bool,
    #[serde(flatten)]
    pub module: ConfigModule,
}

fn default_overlay_signed() -> bool {
    false
}

fn skip_overlay_signed(signed: &bool) -> bool {
    *signed == default_overlay_signed()
}

#[derive(Serialize, Deserialize)]
pub struct ConfigAutoload {
    pub kind: AutoloadKind,
    #[serde(flatten)]
    pub module: ConfigModule,
}

fn is_false(b: &bool) -> bool {
    !b
}
