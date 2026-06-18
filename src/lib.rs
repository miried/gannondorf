use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

#[derive(Debug)]
struct PeI386Image<'data> {
    image_base: u64,
    entry_va: u64,
    sections: Vec<ImageSection<'data>>,
    base_relocations: Vec<u64>,
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
    kind: DirectBranchKind,
    target: u64,
    operand_offset: u64,
    operand_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectBranchKind {
    Call,
    UnconditionalBranch,
    ConditionalBranch,
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
    let image = PeI386Image::parse(image)?;
    let function_va = normalize_address(requested_address, image.image_base);
    let function = image.decode_function(function_va)?;
    write_extracted_object(&function, &image)
}

pub fn discover_function_addresses(image: &[u8]) -> Result<Vec<u64>> {
    let image = PeI386Image::parse(image)?;
    Ok(discover_function_images(&image)?.keys().copied().collect())
}

pub fn extract_function_objects(image: &[u8]) -> Result<Vec<ExtractedObject>> {
    let image = PeI386Image::parse(image)?;
    discover_function_images(&image)?
        .values()
        .map(|function| write_extracted_object(function, &image))
        .collect()
}

impl<'data> PeI386Image<'data> {
    fn parse(image: &'data [u8]) -> Result<Self> {
        let file = PeFile32::parse(image)
            .map_err(|err| UnlinkError::new(format!("failed to parse PE32 image: {err}")))?;
        if file.architecture() != Architecture::I386 {
            return Err(UnlinkError::new(format!(
                "unsupported architecture {:?}; only PE32/i386 is implemented",
                file.architecture()
            )));
        }

        let image_base = file.relative_address_base();
        let entry_va = file.entry();
        let sections = collect_sections(&file)?;
        let base_relocations = collect_base_relocations(&file, image_base)?;

        Ok(Self {
            image_base,
            entry_va,
            sections,
            base_relocations,
        })
    }

    fn decode_function(&self, function_va: u64) -> Result<FunctionImage> {
        let section = find_text_section(&self.sections, function_va).ok_or_else(|| {
            UnlinkError::new(format!(
                "address 0x{function_va:08X} is not inside an executable section"
            ))
        })?;
        decode_function(section, function_va)
    }
}

fn write_extracted_object(
    function: &FunctionImage,
    image: &PeI386Image<'_>,
) -> Result<ExtractedObject> {
    let symbol_name = code_symbol_name(function.va);
    let bytes = write_coff_object(
        function,
        &image.sections,
        &image.base_relocations,
        &symbol_name,
    )?;

    Ok(ExtractedObject {
        symbol_name,
        function_va: function.va,
        function_len: function.bytes.len() as u64,
        bytes,
    })
}

fn discover_function_images(image: &PeI386Image<'_>) -> Result<BTreeMap<u64, FunctionImage>> {
    let mut pending = BTreeSet::new();
    if address_is_text(&image.sections, image.entry_va) {
        pending.insert(image.entry_va);
    }
    pending.extend(collect_text_call_targets(&image.sections));

    let mut functions = BTreeMap::new();
    drain_discovery_queue(image, &mut pending, &mut functions);

    for candidate in collect_i386_prologue_candidates(&image.sections) {
        if !known_function_contains(&functions, candidate) {
            pending.insert(candidate);
        }
    }
    drain_discovery_queue(image, &mut pending, &mut functions);

    if functions.is_empty() {
        return Err(UnlinkError::new(
            "no PE32/i386 functions were discovered in executable sections",
        ));
    }

    Ok(functions)
}

fn drain_discovery_queue(
    image: &PeI386Image<'_>,
    pending: &mut BTreeSet<u64>,
    functions: &mut BTreeMap<u64, FunctionImage>,
) {
    while let Some(function_va) = pending.pop_first() {
        if functions.contains_key(&function_va) || known_function_contains(functions, function_va) {
            continue;
        }

        let Ok(function) = image.decode_function(function_va) else {
            continue;
        };

        queue_function_targets(image, &function, functions, pending);
        functions.insert(function_va, function);
    }
}

fn queue_function_targets(
    image: &PeI386Image<'_>,
    function: &FunctionImage,
    functions: &BTreeMap<u64, FunctionImage>,
    pending: &mut BTreeSet<u64>,
) {
    for instruction in &function.instructions {
        let Some(branch) = &instruction.branch else {
            continue;
        };
        if branch.kind == DirectBranchKind::ConditionalBranch {
            continue;
        }
        if !address_is_text(&image.sections, branch.target) {
            continue;
        }
        if contains_range(function.va, function.bytes.len() as u64, branch.target, 1) {
            continue;
        }
        if functions.contains_key(&branch.target)
            || known_function_contains(functions, branch.target)
        {
            continue;
        }
        pending.insert(branch.target);
    }
}

fn collect_text_call_targets(sections: &[ImageSection<'_>]) -> BTreeSet<u64> {
    let mut targets = BTreeSet::new();
    for section in sections
        .iter()
        .copied()
        .filter(|section| section.kind == SectionKind::Text)
    {
        let mut decoder = Decoder::with_ip(32, section.data, section.address, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                continue;
            }
            let constants = decoder.get_constant_offsets(&instruction);
            if instruction.flow_control() == FlowControl::Call && constants.has_immediate() {
                let target = instruction.near_branch_target();
                if address_is_text(sections, target) {
                    targets.insert(target);
                }
            }
        }
    }
    targets
}

fn collect_i386_prologue_candidates(sections: &[ImageSection<'_>]) -> BTreeSet<u64> {
    let mut candidates = BTreeSet::new();
    for section in sections
        .iter()
        .copied()
        .filter(|section| section.kind == SectionKind::Text)
    {
        for offset in 0..section.data.len() {
            if !has_i386_frame_prologue(section.data, offset) {
                continue;
            }

            let start = if offset >= 2 && section.data[offset - 2..offset] == [0x8B, 0xFF] {
                offset - 2
            } else {
                offset
            };
            candidates.insert(section.address + start as u64);
        }
    }
    candidates
}

fn has_i386_frame_prologue(bytes: &[u8], offset: usize) -> bool {
    bytes
        .get(offset..offset + 3)
        .is_some_and(|bytes| bytes == [0x55, 0x8B, 0xEC] || bytes == [0x55, 0x89, 0xE5])
}

fn known_function_contains(functions: &BTreeMap<u64, FunctionImage>, address: u64) -> bool {
    functions.iter().any(|(&function_va, function)| {
        address != function_va
            && contains_range(function_va, function.bytes.len() as u64, address, 1)
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

    let mut pending = BTreeSet::new();
    let mut instructions = BTreeMap::new();
    let mut function_end = function_va;
    pending.insert(function_va);

    while let Some(block_va) = pending.pop_first() {
        if block_va < function_va {
            continue;
        }

        let mut instruction_va = block_va;
        loop {
            if instructions.contains_key(&instruction_va) {
                break;
            }
            if !contains_range(
                section.address,
                section.data.len() as u64,
                instruction_va,
                1,
            ) {
                return Err(UnlinkError::new(format!(
                    "control flow for function at 0x{function_va:08X} leaves executable section at 0x{instruction_va:08X}"
                )));
            }

            let (instruction, flow_control, next_ip) =
                decode_reachable_instruction(section, instruction_va)?;
            let branch = instruction.branch.clone();
            function_end = function_end.max(next_ip);
            instructions.insert(instruction_va, instruction);

            match flow_control {
                FlowControl::Return
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::Exception => break,
                FlowControl::UnconditionalBranch => {
                    if let Some(branch) = branch {
                        queue_cfg_successor(section, function_va, &mut pending, branch.target);
                    }
                    break;
                }
                FlowControl::ConditionalBranch => {
                    if let Some(branch) = branch {
                        queue_cfg_successor(section, function_va, &mut pending, branch.target);
                    }
                    instruction_va = next_ip;
                }
                FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::Next
                | FlowControl::XbeginXabortXend => {
                    instruction_va = next_ip;
                }
            }
        }
    }

    if instructions.is_empty() {
        return Err(UnlinkError::new(format!(
            "no instructions found for function at 0x{function_va:08X}"
        )));
    }

    let function_len = function_end
        .checked_sub(function_va)
        .ok_or_else(|| UnlinkError::new("decoded function length underflowed"))?
        as usize;
    Ok(FunctionImage {
        va: function_va,
        bytes: bytes[..function_len].to_vec(),
        instructions: instructions.into_values().collect(),
    })
}

fn decode_reachable_instruction(
    section: ImageSection<'_>,
    instruction_va: u64,
) -> Result<(DecodedInstruction, FlowControl, u64)> {
    let section_offset = instruction_va
        .checked_sub(section.address)
        .ok_or_else(|| UnlinkError::new("instruction address precedes section start"))?
        as usize;
    let bytes = section
        .data
        .get(section_offset..)
        .ok_or_else(|| UnlinkError::new("instruction address is outside section data"))?;
    let mut decoder = Decoder::with_ip(32, bytes, instruction_va, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return Err(UnlinkError::new(format!(
            "invalid instruction at 0x{:08X}",
            instruction.ip()
        )));
    }

    let instruction_len = instruction.len() as u64;
    if instruction_len == 0
        || !contains_range(
            section.address,
            section.data.len() as u64,
            instruction.ip(),
            instruction_len,
        )
    {
        return Err(UnlinkError::new(format!(
            "incomplete instruction at 0x{:08X}",
            instruction.ip()
        )));
    }

    let next_ip = instruction.next_ip();
    if next_ip <= instruction.ip() {
        return Err(UnlinkError::new(format!(
            "decoded instruction at 0x{:08X} did not advance",
            instruction.ip()
        )));
    }

    let constants = decoder.get_constant_offsets(&instruction);
    let flow_control = instruction.flow_control();
    let branch = if let Some(kind) = direct_branch_kind(flow_control)
        && constants.has_immediate()
    {
        Some(BranchReference {
            kind,
            target: instruction.near_branch_target(),
            operand_offset: constants.immediate_offset() as u64,
            operand_size: constants.immediate_size() as u32,
        })
    } else {
        None
    };

    Ok((
        DecodedInstruction {
            va: instruction.ip(),
            branch,
        },
        flow_control,
        next_ip,
    ))
}

fn queue_cfg_successor(
    section: ImageSection<'_>,
    function_va: u64,
    pending: &mut BTreeSet<u64>,
    target: u64,
) {
    if target >= function_va
        && contains_range(section.address, section.data.len() as u64, target, 1)
    {
        pending.insert(target);
    }
}

fn direct_branch_kind(flow_control: FlowControl) -> Option<DirectBranchKind> {
    match flow_control {
        FlowControl::Call => Some(DirectBranchKind::Call),
        FlowControl::UnconditionalBranch => Some(DirectBranchKind::UnconditionalBranch),
        FlowControl::ConditionalBranch => Some(DirectBranchKind::ConditionalBranch),
        _ => None,
    }
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
    use super::*;

    #[test]
    fn parses_decimal_and_hex_addresses() {
        assert_eq!(parse_address("4096").unwrap(), 4096);
        assert_eq!(parse_address("0x401000").unwrap(), 0x401000);
        assert_eq!(parse_address("0X1000").unwrap(), 0x1000);
        assert!(parse_address("not-an-address").is_err());
    }

    #[test]
    fn default_output_path_uses_symbol_name() {
        assert_eq!(
            default_output_path("sub_00401000"),
            PathBuf::from("sub_00401000.obj")
        );
    }

    #[test]
    fn normalizes_rvas_against_image_base() {
        assert_eq!(normalize_address(0x1000, 0x400000), 0x401000);
        assert_eq!(normalize_address(0x401000, 0x400000), 0x401000);
    }

    #[test]
    fn range_contains_only_complete_subranges() {
        assert!(contains_range(0x1000, 0x20, 0x1000, 4));
        assert!(contains_range(0x1000, 0x20, 0x101C, 4));
        assert!(!contains_range(0x1000, 0x20, 0x101D, 4));
        assert!(!contains_range(0x1000, 0x20, 0x0FFF, 1));
    }

    #[test]
    fn decodes_conditional_function_with_multiple_returns() {
        #[rustfmt::skip]
        let bytes = [
            0x85, 0xC0,             // test eax, eax
            0x74, 0x06,             // je 0x100A
            0xB8, 0x01, 0, 0, 0,    // mov eax, 1
            0xC3,                   // ret
            0x31, 0xC0,             // xor eax, eax
            0xC3,                   // ret
        ];

        let function = decode_test_function(&bytes).unwrap();

        assert_eq!(function.bytes, bytes);
        assert_eq!(instruction_offsets(&function), [0, 2, 4, 9, 10, 12]);
    }

    #[test]
    fn decodes_backward_loop_to_exit_return() {
        #[rustfmt::skip]
        let bytes = [
            0x31, 0xC0,             // xor eax, eax
            0x40,                   // inc eax
            0x83, 0xF8, 0x03,       // cmp eax, 3
            0x7C, 0xFA,             // jl 0x1002
            0xC3,                   // ret
        ];

        let function = decode_test_function(&bytes).unwrap();

        assert_eq!(function.bytes, bytes);
        assert_eq!(instruction_offsets(&function), [0, 2, 3, 6, 8]);
    }

    #[test]
    fn skips_unreachable_bytes_between_direct_jump_and_return() {
        #[rustfmt::skip]
        let bytes = [
            0xEB, 0x02,             // jmp 0x1004
            0xFF, 0xFF,             // unreachable invalid encoding
            0xC3,                   // ret
        ];

        let function = decode_test_function(&bytes).unwrap();

        assert_eq!(function.bytes, bytes);
        assert_eq!(instruction_offsets(&function), [0, 4]);
    }

    fn decode_test_function(bytes: &[u8]) -> Result<FunctionImage> {
        decode_function(
            ImageSection {
                address: 0x1000,
                data: bytes,
                kind: SectionKind::Text,
            },
            0x1000,
        )
    }

    fn instruction_offsets(function: &FunctionImage) -> Vec<u64> {
        function
            .instructions
            .iter()
            .map(|instruction| instruction.va - function.va)
            .collect()
    }
}
