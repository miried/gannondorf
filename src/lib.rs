use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;

use iced_x86::{Decoder, DecoderOptions, FlowControl};
use object::pe;
use object::read::pe::PeFile32;
use object::read::{Object, ObjectSection};
use object::write::{self, Mangling, SymbolId};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

pub type Result<T> = std::result::Result<T, UnlinkError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkError {
    message: String,
}

impl UnlinkError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for UnlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UnlinkError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedObject {
    pub symbol_name: String,
    pub function_va: u64,
    pub function_len: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct ImageSection<'data> {
    address: u64,
    data: &'data [u8],
    kind: SectionKind,
}

#[derive(Debug, Clone)]
struct FunctionImage {
    va: u64,
    bytes: Vec<u8>,
    instructions: Vec<DecodedInstruction>,
}

#[derive(Debug, Clone)]
struct DecodedInstruction {
    va: u64,
    branch: Option<BranchReference>,
}

#[derive(Debug, Clone)]
struct BranchReference {
    target: u64,
    operand_offset: u64,
    operand_size: u32,
}

pub fn parse_address(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));

    match digits {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => trimmed.parse(),
    }
    .map_err(|_| UnlinkError::new(format!("invalid address `{input}`")))
}

pub fn default_output_path(symbol_name: &str) -> PathBuf {
    PathBuf::from(format!("{symbol_name}.obj"))
}

pub fn extract_function_object(image: &[u8], requested_address: u64) -> Result<ExtractedObject> {
    let file = PeFile32::parse(image)
        .map_err(|err| UnlinkError::new(format!("failed to parse PE32 image: {err}")))?;
    if file.architecture() != Architecture::I386 {
        return Err(UnlinkError::new(format!(
            "unsupported architecture {:?}; only PE32/i386 is implemented",
            file.architecture()
        )));
    }

    let image_base = file.relative_address_base();
    let function_va = normalize_address(requested_address, image_base);
    let sections = collect_sections(&file)?;
    let section = find_text_section(&sections, function_va).ok_or_else(|| {
        UnlinkError::new(format!(
            "address 0x{function_va:08X} is not inside an executable section"
        ))
    })?;
    let function = decode_function(section, function_va)?;
    let base_relocations = collect_base_relocations(&file, image_base)?;
    let symbol_name = code_symbol_name(function_va);
    let bytes = write_coff_object(&function, &sections, &base_relocations, &symbol_name)?;

    Ok(ExtractedObject {
        symbol_name,
        function_va,
        function_len: function.bytes.len() as u64,
        bytes,
    })
}

fn normalize_address(address: u64, image_base: u64) -> u64 {
    if address >= image_base {
        address
    } else {
        image_base + address
    }
}

fn collect_sections<'data>(file: &PeFile32<'data>) -> Result<Vec<ImageSection<'data>>> {
    let mut sections = Vec::new();
    for section in file.sections() {
        sections.push(ImageSection {
            address: section.address(),
            data: section
                .data()
                .map_err(|err| UnlinkError::new(format!("failed to read section data: {err}")))?,
            kind: section.kind(),
        });
    }
    Ok(sections)
}

fn find_text_section<'data>(
    sections: &[ImageSection<'data>],
    address: u64,
) -> Option<ImageSection<'data>> {
    sections.iter().copied().find(|section| {
        section.kind == SectionKind::Text
            && address >= section.address
            && address < section.address.saturating_add(section.data.len() as u64)
    })
}

fn decode_function(section: ImageSection<'_>, function_va: u64) -> Result<FunctionImage> {
    let section_offset = function_va
        .checked_sub(section.address)
        .ok_or_else(|| UnlinkError::new("function address precedes section start"))?
        as usize;
    let bytes = section
        .data
        .get(section_offset..)
        .ok_or_else(|| UnlinkError::new("function address is outside section data"))?;

    let mut decoder = Decoder::with_ip(32, bytes, function_va, DecoderOptions::NONE);
    let mut instructions = Vec::new();

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(UnlinkError::new(format!(
                "invalid instruction at 0x{:08X}",
                instruction.ip()
            )));
        }

        let constants = decoder.get_constant_offsets(&instruction);
        let flow_control = instruction.flow_control();
        let branch = if is_direct_branch(flow_control) && constants.has_immediate() {
            Some(BranchReference {
                target: instruction.near_branch_target(),
                operand_offset: constants.immediate_offset() as u64,
                operand_size: constants.immediate_size() as u32,
            })
        } else {
            None
        };

        let instruction_va = instruction.ip();
        let next_ip = instruction.next_ip();
        instructions.push(DecodedInstruction {
            va: instruction_va,
            branch,
        });

        if flow_control == FlowControl::Return {
            let function_len = next_ip
                .checked_sub(function_va)
                .ok_or_else(|| UnlinkError::new("decoded function length underflowed"))?
                as usize;
            return Ok(FunctionImage {
                va: function_va,
                bytes: bytes[..function_len].to_vec(),
                instructions,
            });
        }
    }

    Err(UnlinkError::new(format!(
        "no return instruction found for function at 0x{function_va:08X}"
    )))
}

fn is_direct_branch(flow_control: FlowControl) -> bool {
    matches!(
        flow_control,
        FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch
    )
}

fn collect_base_relocations(file: &PeFile32<'_>, image_base: u64) -> Result<Vec<u64>> {
    let mut relocation_vas = Vec::new();
    let Some(blocks) = file
        .data_directories()
        .relocation_blocks(file.data(), &file.section_table())
        .map_err(|err| UnlinkError::new(format!("failed to read PE base relocations: {err}")))?
    else {
        return Ok(relocation_vas);
    };

    for block in blocks {
        let block = block.map_err(|err| {
            UnlinkError::new(format!("failed to parse PE relocation block: {err}"))
        })?;
        for relocation in block {
            if relocation.typ == pe::IMAGE_REL_BASED_HIGHLOW {
                relocation_vas.push(image_base + u64::from(relocation.virtual_address));
            }
        }
    }

    Ok(relocation_vas)
}

fn write_coff_object(
    function: &FunctionImage,
    sections: &[ImageSection<'_>],
    base_relocations: &[u64],
    symbol_name: &str,
) -> Result<Vec<u8>> {
    let mut object = write::Object::new(BinaryFormat::Coff, Architecture::I386, Endianness::Little);
    object.set_mangling(Mangling::None);

    let text = object.section_id(write::StandardSection::Text);
    object.append_section_data(text, &function.bytes, 16);
    object.add_symbol(write::Symbol {
        name: symbol_name.as_bytes().to_vec(),
        value: 0,
        size: function.bytes.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });

    let mut symbols = HashMap::new();
    let mut relocated_offsets = HashSet::new();

    for &relocation_va in base_relocations {
        if !contains_range(function.va, function.bytes.len() as u64, relocation_va, 4) {
            continue;
        }
        let offset = relocation_va - function.va;
        let target_va = read_u32(&function.bytes, offset as usize)? as u64;
        let kind = if address_is_text(sections, target_va) {
            SymbolKind::Text
        } else {
            SymbolKind::Data
        };
        let symbol = target_symbol(&mut object, &mut symbols, kind, target_va);
        write_u32(object.section_mut(text).data_mut(), offset as usize, 0)?;
        object
            .add_relocation(
                text,
                write::Relocation {
                    offset,
                    symbol,
                    addend: 0,
                    flags: RelocationFlags::Generic {
                        kind: RelocationKind::Absolute,
                        encoding: RelocationEncoding::Generic,
                        size: 32,
                    },
                },
            )
            .map_err(|err| UnlinkError::new(format!("failed to add absolute relocation: {err}")))?;
        relocated_offsets.insert(offset);
    }

    for instruction in &function.instructions {
        let Some(branch) = &instruction.branch else {
            continue;
        };
        if contains_range(function.va, function.bytes.len() as u64, branch.target, 1) {
            continue;
        }
        if branch.operand_size != 4 {
            return Err(UnlinkError::new(format!(
                "unsupported external branch relocation size {} at 0x{:08X}",
                branch.operand_size, instruction.va
            )));
        }

        let offset = instruction
            .va
            .checked_sub(function.va)
            .and_then(|base| base.checked_add(branch.operand_offset))
            .ok_or_else(|| UnlinkError::new("branch relocation offset underflowed"))?;
        if !relocated_offsets.insert(offset) {
            continue;
        }

        let symbol = target_symbol(&mut object, &mut symbols, SymbolKind::Text, branch.target);
        write_u32(object.section_mut(text).data_mut(), offset as usize, 0)?;
        object
            .add_relocation(
                text,
                write::Relocation {
                    offset,
                    symbol,
                    addend: -4,
                    flags: RelocationFlags::Generic {
                        kind: RelocationKind::Relative,
                        encoding: RelocationEncoding::Generic,
                        size: 32,
                    },
                },
            )
            .map_err(|err| UnlinkError::new(format!("failed to add relative relocation: {err}")))?;
    }

    object
        .write()
        .map_err(|err| UnlinkError::new(format!("failed to write COFF object: {err}")))
}

fn target_symbol(
    object: &mut write::Object<'_>,
    symbols: &mut HashMap<(SymbolKind, u64), SymbolId>,
    kind: SymbolKind,
    va: u64,
) -> SymbolId {
    if let Some(symbol) = symbols.get(&(kind, va)) {
        return *symbol;
    }

    let name = match kind {
        SymbolKind::Text => code_symbol_name(va),
        _ => data_symbol_name(va),
    };
    let symbol = object.add_symbol(write::Symbol {
        name: name.into_bytes(),
        value: 0,
        size: 0,
        kind,
        scope: SymbolScope::Linkage,
        weak: false,
        section: write::SymbolSection::Undefined,
        flags: SymbolFlags::None,
    });
    symbols.insert((kind, va), symbol);
    symbol
}

fn contains_range(start: u64, len: u64, address: u64, size: u64) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    let Some(address_end) = address.checked_add(size) else {
        return false;
    };
    address >= start && address_end <= end
}

fn address_is_text(sections: &[ImageSection<'_>], address: u64) -> bool {
    find_text_section(sections, address).is_some()
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| UnlinkError::new("relocation offset is outside function bytes"))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("slice length was checked"),
    ))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let destination = bytes
        .get_mut(offset..offset + 4)
        .ok_or_else(|| UnlinkError::new("relocation offset is outside function bytes"))?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn code_symbol_name(va: u64) -> String {
    format!("sub_{va:08X}")
}

fn data_symbol_name(va: u64) -> String {
    format!("data_{va:08X}")
}

#[cfg(test)]
mod tests {
    use object::read::{Object as _, ObjectSection as _, ObjectSymbol as _};
    use object::{Architecture, BinaryFormat, RelocationKind};

    use super::*;

    const TEST00: &[u8] = include_bytes!("../tests/TEST00.exe");

    #[test]
    fn parses_decimal_and_hex_addresses() {
        assert_eq!(parse_address("4096").unwrap(), 4096);
        assert_eq!(parse_address("0x401000").unwrap(), 0x401000);
        assert_eq!(parse_address("0X1000").unwrap(), 0x1000);
        assert!(parse_address("not-an-address").is_err());
    }

    #[test]
    fn extracts_function_without_relocations() {
        let extracted = extract_function_object(TEST00, 0x401000).unwrap();
        assert_eq!(extracted.symbol_name, "sub_00401000");
        assert_eq!(extracted.function_len, 0x17);

        let file = object::File::parse(&*extracted.bytes).unwrap();
        assert_eq!(file.format(), BinaryFormat::Coff);
        assert_eq!(file.architecture(), Architecture::I386);

        let text = file.section_by_name(".text").unwrap();
        assert_eq!(text.data().unwrap().len(), 0x17);
        assert_eq!(text.relocations().count(), 0);
        assert!(
            file.symbols()
                .any(|symbol| symbol.name() == Ok("sub_00401000"))
        );
    }

    #[test]
    fn extracts_function_with_absolute_relocations() {
        let extracted = extract_function_object(TEST00, 0x401017).unwrap();
        let file = object::File::parse(&*extracted.bytes).unwrap();
        let text = file.section_by_name(".text").unwrap();
        let relocations: Vec<_> = text.relocations().collect();

        assert_eq!(relocations.len(), 2);
        assert!(
            relocations
                .iter()
                .all(|(_, relocation)| relocation.kind() == RelocationKind::Absolute)
        );
        assert!(
            file.symbols()
                .any(|symbol| symbol.name() == Ok("data_00406030"))
        );

        let data = text.data().unwrap();
        assert_eq!(&data[0x0B..0x0F], &[0, 0, 0, 0]);
        assert_eq!(&data[0x10..0x14], &[0, 0, 0, 0]);
    }

    #[test]
    fn extracts_function_with_relative_call_relocation() {
        let extracted = extract_function_object(TEST00, 0x401035).unwrap();
        let file = object::File::parse(&*extracted.bytes).unwrap();
        let text = file.section_by_name(".text").unwrap();
        let relocations: Vec<_> = text.relocations().collect();

        assert_eq!(relocations.len(), 1);
        assert_eq!(relocations[0].0, 0x0B);
        assert_eq!(relocations[0].1.kind(), RelocationKind::Relative);
        assert!(
            file.symbols()
                .any(|symbol| symbol.name() == Ok("sub_00401000"))
        );
        assert_eq!(&text.data().unwrap()[0x0B..0x0F], &[0, 0, 0, 0]);
    }

    #[test]
    fn treats_small_addresses_as_rvas() {
        let by_va = extract_function_object(TEST00, 0x401000).unwrap();
        let by_rva = extract_function_object(TEST00, 0x1000).unwrap();
        assert_eq!(by_va.bytes, by_rva.bytes);
    }

    #[test]
    fn errors_when_address_is_not_executable() {
        let error = extract_function_object(TEST00, 0x406030).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("is not inside an executable section")
        );
    }
}
