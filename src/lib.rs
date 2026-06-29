use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, Mnemonic, OpKind,
    Register,
};
use object::endian::LittleEndian as LE;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredFunction {
    pub symbol_name: String,
    pub function_va: u64,
    pub function_len: u64,
    pub instructions: Vec<DisassembledInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassembledInstruction {
    pub va: u64,
    pub len: u32,
    pub text: String,
}

#[derive(Debug)]
struct PeI386Image<'data> {
    image_base: u64,
    entry_va: u64,
    sections: Vec<ImageSection<'data>>,
    base_relocations: Vec<u64>,
    no_return_imports: BTreeSet<u64>,
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
    len: u32,
    text: String,
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

pub fn discover_functions(image: &[u8]) -> Result<Vec<DiscoveredFunction>> {
    let image = PeI386Image::parse(image)?;
    Ok(discover_function_images(&image)?
        .values()
        .map(describe_discovered_function)
        .collect())
}

pub fn extract_function_objects(image: &[u8]) -> Result<Vec<ExtractedObject>> {
    let image = PeI386Image::parse(image)?;
    discover_function_images(&image)?
        .values()
        .filter(|function| function_is_extractable(function))
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
        let no_return_imports = collect_no_return_imports(&file, image_base)?;

        Ok(Self {
            image_base,
            entry_va,
            sections,
            base_relocations,
            no_return_imports,
        })
    }

    fn decode_function(&self, function_va: u64) -> Result<FunctionImage> {
        self.decode_function_with_boundaries(function_va, &BTreeSet::new())
    }

    fn decode_function_with_boundaries(
        &self,
        function_va: u64,
        function_starts: &BTreeSet<u64>,
    ) -> Result<FunctionImage> {
        let section = find_text_section(&self.sections, function_va).ok_or_else(|| {
            UnlinkError::new(format!(
                "address 0x{function_va:08X} is not inside an executable section"
            ))
        })?;
        decode_function(
            section,
            &self.sections,
            function_va,
            function_starts,
            &self.no_return_imports,
        )
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

fn describe_discovered_function(function: &FunctionImage) -> DiscoveredFunction {
    DiscoveredFunction {
        symbol_name: code_symbol_name(function.va),
        function_va: function.va,
        function_len: function.bytes.len() as u64,
        instructions: function
            .instructions
            .iter()
            .map(|instruction| DisassembledInstruction {
                va: instruction.va,
                len: instruction.len,
                text: format_instruction(function, instruction),
            })
            .collect(),
    }
}

fn format_instruction(function: &FunctionImage, instruction: &DecodedInstruction) -> String {
    let _ = function;
    instruction.text.clone()
}

fn format_iced_instruction(instruction: &Instruction) -> String {
    let mut formatter = IntelFormatter::new();
    let options = formatter.options_mut();
    options.set_uppercase_hex(false);
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_uppercase_mnemonics(true);
    options.set_uppercase_registers(true);
    options.set_space_after_operand_separator(true);

    let mut output = String::new();
    formatter.format(instruction, &mut output);
    output
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

        let mut function_starts = pending.clone();
        function_starts.extend(functions.keys().copied());
        function_starts.insert(function_va);

        let Ok(function) = image.decode_function_with_boundaries(function_va, &function_starts)
        else {
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
        if function
            .instructions
            .iter()
            .any(|instruction| instruction.va == branch.target)
        {
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

fn collect_no_return_imports(file: &PeFile32<'_>, image_base: u64) -> Result<BTreeSet<u64>> {
    let mut imports = BTreeSet::new();
    let Some(import_table) = file
        .import_table()
        .map_err(|err| UnlinkError::new(format!("failed to read PE imports: {err}")))?
    else {
        return Ok(imports);
    };

    let mut descriptors = import_table
        .descriptors()
        .map_err(|err| UnlinkError::new(format!("failed to read PE import descriptors: {err}")))?;
    while let Some(descriptor) = descriptors
        .next()
        .map_err(|err| UnlinkError::new(format!("failed to parse PE import descriptor: {err}")))?
    {
        let first_thunk = descriptor.first_thunk.get(LE);
        let lookup_thunk = match descriptor.original_first_thunk.get(LE) {
            0 => first_thunk,
            rva => rva,
        };
        if first_thunk == 0 || lookup_thunk == 0 {
            continue;
        }

        let mut thunks = import_table.thunks(lookup_thunk).map_err(|err| {
            UnlinkError::new(format!("failed to read PE import thunk list: {err}"))
        })?;
        let mut index = 0u64;
        while let Some(thunk) = thunks
            .next::<pe::ImageNtHeaders32>()
            .map_err(|err| UnlinkError::new(format!("failed to parse PE import thunk: {err}")))?
        {
            if let Ok(object::read::pe::Import::Name(_, name)) =
                import_table.import::<pe::ImageNtHeaders32>(thunk)
                && imported_symbol_is_no_return(name)
            {
                imports.insert(image_base + u64::from(first_thunk) + index * 4);
            }
            index += 1;
        }
    }

    Ok(imports)
}

fn imported_symbol_is_no_return(name: &[u8]) -> bool {
    matches!(
        name,
        b"ExitProcess"
            | b"TerminateProcess"
            | b"FatalExit"
            | b"_exit"
            | b"exit"
            | b"abort"
            | b"quick_exit"
    )
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

fn decode_function(
    section: ImageSection<'_>,
    sections: &[ImageSection<'_>],
    function_va: u64,
    function_starts: &BTreeSet<u64>,
    no_return_imports: &BTreeSet<u64>,
) -> Result<FunctionImage> {
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
    let allow_lower_blocks = !function_starts.is_empty();
    pending.insert(function_va);

    while let Some(block_va) = pending.pop_first() {
        let mut instruction_va = block_va;
        let mut block_instructions = Vec::new();
        loop {
            if instruction_va != function_va && function_starts.contains(&instruction_va) {
                break;
            }
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

            let (instruction, decoded, flow_control, next_ip) =
                decode_reachable_instruction(section, instruction_va)?;
            let branch = instruction.branch.clone();
            function_end = function_end.max(next_ip);
            block_instructions.push(decoded);
            instructions.insert(instruction_va, instruction);

            match flow_control {
                FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => break,
                FlowControl::IndirectBranch => {
                    for target in infer_jump_table_targets(section, &block_instructions) {
                        queue_cfg_successor(
                            section,
                            function_va,
                            &mut pending,
                            target,
                            allow_lower_blocks,
                        );
                    }
                    break;
                }
                FlowControl::UnconditionalBranch => {
                    if let Some(branch) = branch {
                        if !branch_crosses_known_function_start(
                            function_va,
                            next_ip,
                            branch.target,
                            function_starts,
                        ) {
                            queue_cfg_successor(
                                section,
                                function_va,
                                &mut pending,
                                branch.target,
                                allow_lower_blocks,
                            );
                        }
                    }
                    break;
                }
                FlowControl::ConditionalBranch => {
                    if let Some(branch) = branch {
                        queue_cfg_successor(
                            section,
                            function_va,
                            &mut pending,
                            branch.target,
                            allow_lower_blocks,
                        );
                    }
                    instruction_va = next_ip;
                }
                FlowControl::Call | FlowControl::IndirectCall => {
                    if call_does_not_return(
                        sections,
                        no_return_imports,
                        section,
                        &block_instructions,
                        branch.as_ref(),
                        next_ip,
                    ) {
                        break;
                    }
                    instruction_va = next_ip;
                }
                FlowControl::Next | FlowControl::XbeginXabortXend => {
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

fn branch_crosses_known_function_start(
    function_va: u64,
    next_ip: u64,
    target: u64,
    function_starts: &BTreeSet<u64>,
) -> bool {
    if target <= next_ip {
        return false;
    }

    function_starts
        .range(next_ip..target)
        .any(|&start| start != function_va)
}

fn decode_reachable_instruction(
    section: ImageSection<'_>,
    instruction_va: u64,
) -> Result<(DecodedInstruction, Instruction, FlowControl, u64)> {
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

    let next_ip = adjusted_next_ip_for_wait_prefixed_x87(section, &instruction)?;
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
            len: instruction_len as u32,
            text: format_iced_instruction(&instruction),
            branch,
        },
        instruction,
        flow_control,
        next_ip,
    ))
}

fn adjusted_next_ip_for_wait_prefixed_x87(
    section: ImageSection<'_>,
    instruction: &Instruction,
) -> Result<u64> {
    let next_ip = instruction.next_ip();
    if instruction.mnemonic() != Mnemonic::Wait {
        return Ok(next_ip);
    }

    let Some(&next_byte) = byte_at(section, next_ip) else {
        return Ok(next_ip);
    };
    if !(0xD8..=0xDF).contains(&next_byte) {
        return Ok(next_ip);
    }

    let section_offset = next_ip
        .checked_sub(section.address)
        .ok_or_else(|| UnlinkError::new("instruction address precedes section start"))?
        as usize;
    let bytes = section
        .data
        .get(section_offset..)
        .ok_or_else(|| UnlinkError::new("instruction address is outside section data"))?;
    let mut decoder = Decoder::with_ip(32, bytes, next_ip, DecoderOptions::NONE);
    let following = decoder.decode();
    if following.is_invalid() || following.len() == 0 {
        return Ok(next_ip);
    }

    Ok(following.next_ip())
}

fn infer_jump_table_targets(
    section: ImageSection<'_>,
    block_instructions: &[Instruction],
) -> Vec<u64> {
    let Some(jump) = block_instructions.last() else {
        return Vec::new();
    };
    if jump.mnemonic() != Mnemonic::Jmp
        || jump.op_kind(0) != OpKind::Memory
        || jump.memory_base() != Register::None
        || jump.memory_index_scale() != 4
    {
        return Vec::new();
    }

    let index = normalize_register32(jump.memory_index());
    if index == Register::None {
        return Vec::new();
    }

    let table_va = jump.memory_displacement64();
    if let Some(max_index) = find_index_upper_bound(block_instructions, index) {
        return read_jump_table_targets(section, table_va, max_index.saturating_add(1));
    }

    let Some(remap) = find_byte_remap(block_instructions, index) else {
        return Vec::new();
    };
    let Some(max_source_index) = find_index_upper_bound(block_instructions, remap.source_index)
    else {
        return Vec::new();
    };

    let mut targets = BTreeSet::new();
    for offset in 0..=max_source_index {
        let Some(&table_index) = byte_at(section, remap.map_va.saturating_add(offset)) else {
            break;
        };
        targets.extend(read_jump_table_targets(
            section,
            table_va.saturating_add(u64::from(table_index) * 4),
            1,
        ));
    }
    targets.into_iter().collect()
}

#[derive(Debug, Clone, Copy)]
struct ByteRemap {
    source_index: Register,
    map_va: u64,
}

fn find_byte_remap(block_instructions: &[Instruction], table_index: Register) -> Option<ByteRemap> {
    block_instructions.iter().rev().find_map(|instruction| {
        if instruction.mnemonic() != Mnemonic::Mov
            || normalize_register32(instruction.op0_register()) != table_index
            || !register_is_low8(instruction.op0_register())
            || instruction.op_kind(1) != OpKind::Memory
            || instruction.memory_index() != Register::None
        {
            return None;
        }

        let source_index = normalize_register32(instruction.memory_base());
        if source_index == Register::None {
            return None;
        }

        Some(ByteRemap {
            source_index,
            map_va: instruction.memory_displacement64(),
        })
    })
}

fn find_index_upper_bound(block_instructions: &[Instruction], register: Register) -> Option<u64> {
    const MAX_INFERRED_JUMP_TABLE_ENTRIES: u64 = 1024;

    let mut current = register;
    for instruction in block_instructions.iter().rev() {
        if normalize_register32(instruction.op0_register()) != current {
            continue;
        }

        match instruction.mnemonic() {
            Mnemonic::Cmp => {
                return immediate_operand(instruction, 1).filter(|&max_index| {
                    max_index.saturating_add(1) <= MAX_INFERRED_JUMP_TABLE_ENTRIES
                });
            }
            Mnemonic::And => {
                return immediate_operand(instruction, 1)
                    .filter(|&mask| mask.saturating_add(1) <= MAX_INFERRED_JUMP_TABLE_ENTRIES);
            }
            Mnemonic::Mov => {
                let source = normalize_register32(instruction.op1_register());
                if source == Register::None {
                    return None;
                }
                current = source;
            }
            _ => return None,
        }
    }

    None
}

fn immediate_operand(instruction: &Instruction, operand: u32) -> Option<u64> {
    if matches!(
        instruction.op_kind(operand),
        OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate16
            | OpKind::Immediate32
    ) {
        Some(instruction.immediate(operand))
    } else {
        None
    }
}

fn call_does_not_return(
    sections: &[ImageSection<'_>],
    no_return_imports: &BTreeSet<u64>,
    section: ImageSection<'_>,
    block_instructions: &[Instruction],
    branch: Option<&BranchReference>,
    next_ip: u64,
) -> bool {
    let Some(instruction) = block_instructions.last() else {
        return false;
    };

    match instruction.flow_control() {
        FlowControl::Call => branch.is_some_and(|branch| {
            branch.kind == DirectBranchKind::Call
                && direct_call_target_is_no_return(sections, no_return_imports, branch.target)
        }),
        FlowControl::IndirectCall => indirect_call_target_is_no_return(
            sections,
            no_return_imports,
            section,
            block_instructions,
            next_ip,
        ),
        _ => false,
    }
}

fn direct_call_target_is_no_return(
    sections: &[ImageSection<'_>],
    no_return_imports: &BTreeSet<u64>,
    target: u64,
) -> bool {
    no_return_imports.contains(&target)
        || target_is_crt_no_return_exit_wrapper(sections, no_return_imports, target)
}

fn indirect_call_target_is_no_return(
    sections: &[ImageSection<'_>],
    no_return_imports: &BTreeSet<u64>,
    section: ImageSection<'_>,
    block_instructions: &[Instruction],
    next_ip: u64,
) -> bool {
    let Some(instruction) = block_instructions.last() else {
        return false;
    };
    let Some(target) = absolute_memory_operand(instruction) else {
        return false;
    };

    if no_return_imports.contains(&target) {
        return true;
    }

    if indirect_call_is_msvc_exit_dispatch(sections, target, section, block_instructions, next_ip) {
        return true;
    }

    let Some(pointer) = read_u32_at_sections(sections, target).map(u64::from) else {
        return false;
    };
    no_return_imports.contains(&pointer)
        || target_is_crt_no_return_exit_wrapper(sections, no_return_imports, pointer)
}

fn indirect_call_is_msvc_exit_dispatch(
    sections: &[ImageSection<'_>],
    target: u64,
    section: ImageSection<'_>,
    block_instructions: &[Instruction],
    next_ip: u64,
) -> bool {
    if !contains_non_text_range(sections, target, 4) {
        return false;
    }

    let Some(previous) = block_instructions.iter().rev().nth(1) else {
        return false;
    };

    instruction_pushes_minus_one(previous)
        && next_instruction_cleans_single_stack_argument(section, next_ip)
}

fn next_instruction_cleans_single_stack_argument(section: ImageSection<'_>, next_ip: u64) -> bool {
    let Some(instructions) = decode_instruction_prefix(section, next_ip, 1) else {
        return false;
    };
    let instruction = &instructions[0];
    instruction.mnemonic() == Mnemonic::Add
        && instruction.op0_register() == Register::ESP
        && immediate_operand(instruction, 1) == Some(4)
}

fn target_is_crt_no_return_exit_wrapper(
    sections: &[ImageSection<'_>],
    no_return_imports: &BTreeSet<u64>,
    target: u64,
) -> bool {
    let Some(section) = find_text_section(sections, target) else {
        return false;
    };
    let Some(instructions) = decode_instruction_prefix(section, target, 5) else {
        return false;
    };
    let [load_arg, push_zero_1, push_zero_2, push_arg, call] = instructions.as_slice() else {
        return false;
    };

    load_arg.mnemonic() == Mnemonic::Mov
        && load_arg.op0_register() == Register::EAX
        && load_arg.op_kind(1) == OpKind::Memory
        && load_arg.memory_base() == Register::ESP
        && load_arg.memory_index() == Register::None
        && load_arg.memory_displacement64() == 4
        && instruction_pushes_immediate(push_zero_1, 0)
        && instruction_pushes_immediate(push_zero_2, 0)
        && push_arg.mnemonic() == Mnemonic::Push
        && push_arg.op0_register() == Register::EAX
        && call.flow_control() == FlowControl::Call
        && (call.op_kind(0) == OpKind::NearBranch16
            || call.op_kind(0) == OpKind::NearBranch32
            || direct_call_target_is_no_return(
                sections,
                no_return_imports,
                call.near_branch_target(),
            ))
}

fn decode_instruction_prefix(
    section: ImageSection<'_>,
    start_va: u64,
    count: usize,
) -> Option<Vec<Instruction>> {
    let offset = start_va.checked_sub(section.address)? as usize;
    let bytes = section.data.get(offset..)?;
    let mut decoder = Decoder::with_ip(32, bytes, start_va, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    for _ in 0..count {
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.len() == 0 {
            return None;
        }
        instructions.push(instruction);
    }
    Some(instructions)
}

fn instruction_pushes_immediate(instruction: &Instruction, value: u64) -> bool {
    instruction.mnemonic() == Mnemonic::Push && immediate_operand(instruction, 0) == Some(value)
}

fn instruction_pushes_minus_one(instruction: &Instruction) -> bool {
    instruction.mnemonic() == Mnemonic::Push
        && immediate_operand(instruction, 0)
            .is_some_and(|value| matches!(value, 0xFF | 0xFFFF_FFFF | u64::MAX))
}

fn absolute_memory_operand(instruction: &Instruction) -> Option<u64> {
    if instruction.op_kind(0) == OpKind::Memory
        && instruction.memory_base() == Register::None
        && instruction.memory_index() == Register::None
    {
        Some(instruction.memory_displacement64())
    } else {
        None
    }
}

fn read_jump_table_targets(section: ImageSection<'_>, table_va: u64, entry_count: u64) -> Vec<u64> {
    let mut targets = BTreeSet::new();
    for index in 0..entry_count {
        let entry_va = table_va.saturating_add(index.saturating_mul(4));
        let Some(target) = read_u32_at(section, entry_va) else {
            break;
        };
        let target = u64::from(target);
        if contains_range(section.address, section.data.len() as u64, target, 1) {
            targets.insert(target);
        }
    }
    targets.into_iter().collect()
}

fn byte_at(section: ImageSection<'_>, va: u64) -> Option<&u8> {
    let offset = va.checked_sub(section.address)? as usize;
    section.data.get(offset)
}

fn read_u32_at(section: ImageSection<'_>, va: u64) -> Option<u32> {
    let offset = va.checked_sub(section.address)? as usize;
    let bytes = section.data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u32_at_sections(sections: &[ImageSection<'_>], va: u64) -> Option<u32> {
    sections
        .iter()
        .copied()
        .find(|section| contains_range(section.address, section.data.len() as u64, va, 4))
        .and_then(|section| read_u32_at(section, va))
}

fn contains_non_text_range(sections: &[ImageSection<'_>], va: u64, len: u64) -> bool {
    sections.iter().any(|section| {
        section.kind != SectionKind::Text
            && contains_range(section.address, section.data.len() as u64, va, len)
    })
}

fn register_is_low8(register: Register) -> bool {
    matches!(
        register,
        Register::AL | Register::CL | Register::DL | Register::BL
    )
}

fn normalize_register32(register: Register) -> Register {
    match register {
        Register::AL | Register::AH | Register::AX | Register::EAX => Register::EAX,
        Register::CL | Register::CH | Register::CX | Register::ECX => Register::ECX,
        Register::DL | Register::DH | Register::DX | Register::EDX => Register::EDX,
        Register::BL | Register::BH | Register::BX | Register::EBX => Register::EBX,
        Register::SP | Register::ESP => Register::ESP,
        Register::BP | Register::EBP => Register::EBP,
        Register::SI | Register::ESI => Register::ESI,
        Register::DI | Register::EDI => Register::EDI,
        _ => Register::None,
    }
}

fn queue_cfg_successor(
    section: ImageSection<'_>,
    function_va: u64,
    pending: &mut BTreeSet<u64>,
    target: u64,
    allow_lower_blocks: bool,
) {
    if !contains_range(section.address, section.data.len() as u64, target, 1) {
        return;
    }
    if target >= function_va
        || (allow_lower_blocks && target_is_lower_return_block(section, function_va, target))
    {
        pending.insert(target);
    }
}

fn target_is_lower_return_block(section: ImageSection<'_>, function_va: u64, target: u64) -> bool {
    if target >= function_va {
        return false;
    }

    const MAX_LOWER_RETURN_BLOCK_BYTES: u64 = 0x40;
    const MAX_LOWER_RETURN_BLOCK_INSTRUCTIONS: usize = 8;

    let mut instruction_va = target;
    for _ in 0..MAX_LOWER_RETURN_BLOCK_INSTRUCTIONS {
        if instruction_va >= function_va
            || instruction_va.saturating_sub(target) > MAX_LOWER_RETURN_BLOCK_BYTES
        {
            return false;
        }

        let Ok((_, _, flow_control, next_ip)) =
            decode_reachable_instruction(section, instruction_va)
        else {
            return false;
        };

        match flow_control {
            FlowControl::Return => return true,
            FlowControl::Next | FlowControl::XbeginXabortXend => instruction_va = next_ip,
            _ => return false,
        }
    }

    false
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
    if !function_is_extractable(function) {
        return Err(UnlinkError::new(format!(
            "function 0x{:08X} contains control flow that cannot be represented as a standalone COFF object",
            function.va
        )));
    }

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

fn function_is_extractable(function: &FunctionImage) -> bool {
    function.instructions.iter().all(|instruction| {
        contains_range(
            function.va,
            function.bytes.len() as u64,
            instruction.va,
            u64::from(instruction.len),
        ) && instruction.branch.as_ref().is_none_or(|branch| {
            branch.operand_size == 4
                || contains_range(function.va, function.bytes.len() as u64, branch.target, 1)
        })
    })
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

    #[test]
    fn stops_unconditional_jump_before_intervening_known_function_start() {
        #[rustfmt::skip]
        let bytes = [
            0xE9, 0x0B, 0x00, 0x00, 0x00, // jmp 0x1010
            0xCC, 0xCC, 0xCC,             // padding before another function
            0xC3,                         // known function at 0x1008
            0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC,
            0xC3,                         // tail target at 0x1010
        ];

        let function = decode_test_function_with_starts(&bytes, &[0x1000, 0x1008]).unwrap();

        assert_eq!(function.bytes, bytes[..5]);
        assert_eq!(instruction_offsets(&function), [0]);
    }

    #[test]
    fn stops_linear_decode_at_next_known_function_start() {
        #[rustfmt::skip]
        let bytes = [
            0x90, // nop
            0xC3, // known next function start at 0x1001
        ];

        let function = decode_test_function_with_starts(&bytes, &[0x1000, 0x1001]).unwrap();

        assert_eq!(function.bytes, bytes[..1]);
        assert_eq!(instruction_offsets(&function), [0]);
    }

    #[test]
    fn follows_absolute_i386_jump_table_entries() {
        #[rustfmt::skip]
        let bytes = [
            0x83, 0xF8, 0x01,                         // cmp eax, 1
            0x77, 0x13,                               // ja 0x1018
            0xFF, 0x24, 0x85, 0x20, 0x10, 0x00, 0x00, // jmp dword ptr [eax*4+0x1020]
            0xB8, 0x01, 0x00, 0x00, 0x00,             // mov eax, 1
            0xC3,                                     // ret
            0xB8, 0x02, 0x00, 0x00, 0x00,             // mov eax, 2
            0xC3,                                     // ret
            0x31, 0xC0,                               // xor eax, eax
            0xC3,                                     // ret
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0x0C, 0x10, 0x00, 0x00,                   // table[0] = 0x100C
            0x12, 0x10, 0x00, 0x00,                   // table[1] = 0x1012
        ];

        let function = decode_test_function(&bytes).unwrap();

        assert_eq!(
            instruction_offsets(&function),
            [0, 3, 5, 0x0C, 0x11, 0x12, 0x17, 0x18, 0x1A]
        );
    }

    #[test]
    fn follows_and_bounded_jump_table_entries() {
        #[rustfmt::skip]
        let bytes = [
            0x8B, 0xD1,                               // mov edx, ecx
            0x83, 0xE2, 0x03,                         // and edx, 3
            0xFF, 0x24, 0x95, 0x24, 0x10, 0x00, 0x00, // jmp dword ptr [edx*4+0x1024]
            0xB8, 0x00, 0x00, 0x00, 0x00,             // mov eax, 0
            0xC3,                                     // ret
            0xB8, 0x01, 0x00, 0x00, 0x00,             // mov eax, 1
            0xC3,                                     // ret
            0xB8, 0x02, 0x00, 0x00, 0x00,             // mov eax, 2
            0xC3,                                     // ret
            0xB8, 0x03, 0x00, 0x00, 0x00,             // mov eax, 3
            0xC3,                                     // ret
            0x0C, 0x10, 0x00, 0x00,                   // table[0] = 0x100C
            0x12, 0x10, 0x00, 0x00,                   // table[1] = 0x1012
            0x18, 0x10, 0x00, 0x00,                   // table[2] = 0x1018
            0x1E, 0x10, 0x00, 0x00,                   // table[3] = 0x101E
        ];

        let function = decode_test_function(&bytes).unwrap();

        assert_eq!(
            instruction_offsets(&function),
            [0, 2, 5, 0x0C, 0x11, 0x12, 0x17, 0x18, 0x1D, 0x1E, 0x23]
        );
    }

    #[test]
    fn follows_jump_table_after_index_register_copy() {
        #[rustfmt::skip]
        let bytes = [
            0x83, 0xF9, 0x01,                         // cmp ecx, 1
            0x8B, 0xC1,                               // mov eax, ecx
            0x77, 0x13,                               // ja 0x101A
            0xFF, 0x24, 0x85, 0x20, 0x10, 0x00, 0x00, // jmp dword ptr [eax*4+0x1020]
            0xB8, 0x0A, 0x00, 0x00, 0x00,             // mov eax, 10
            0xC3,                                     // ret
            0xB8, 0x0B, 0x00, 0x00, 0x00,             // mov eax, 11
            0xC3,                                     // ret
            0x31, 0xC0,                               // xor eax, eax
            0xC3,                                     // ret
            0xCC, 0xCC, 0xCC,
            0x0E, 0x10, 0x00, 0x00,                   // table[0] = 0x100E
            0x14, 0x10, 0x00, 0x00,                   // table[1] = 0x1014
        ];

        let function = decode_test_function(&bytes).unwrap();

        assert_eq!(
            instruction_offsets(&function),
            [0, 3, 5, 7, 0x0E, 0x13, 0x14, 0x19, 0x1A, 0x1C]
        );
    }

    #[test]
    fn groups_wait_prefixed_x87_for_ghidra_compatible_discovery() {
        #[rustfmt::skip]
        let bytes = [
            0x9B,                         // wait prefix emitted by Ghidra as FSTCW/FSTSW line
            0xD9, 0x7C, 0x24, 0x00,       // fnstcw [esp]
            0xC3,                         // ret
        ];

        let function = decode_test_function(&bytes).unwrap();

        assert_eq!(function.bytes, bytes);
        assert_eq!(instruction_offsets(&function), [0, 5]);
        assert_eq!(function.instructions[0].len, 1);
    }

    #[test]
    fn stops_after_no_return_import_call() {
        #[rustfmt::skip]
        let bytes = [
            0x6A, 0x00,                         // push 0
            0xFF, 0x15, 0x20, 0x10, 0x00, 0x00, // call dword ptr [0x1020]
            0x58,                               // unreachable pop eax
            0xC3,                               // unreachable ret
        ];

        let function = decode_test_function_with_no_return_imports(&bytes, &[0x1020]).unwrap();

        assert_eq!(function.bytes, bytes[..8]);
        assert_eq!(instruction_offsets(&function), [0, 2]);
    }

    #[test]
    fn stops_after_msvc_exit_dispatch_call() {
        #[rustfmt::skip]
        let text_bytes = [
            0x6A, 0xFF,                         // push -1
            0xFF, 0x15, 0x20, 0x20, 0x00, 0x00, // call dword ptr [0x2020]
            0x83, 0xC4, 0x04,                   // unreachable add esp, 4
            0xC3,                               // unreachable ret
        ];
        let data_bytes = [0u8; 0x24];
        let text = ImageSection {
            address: 0x1000,
            data: &text_bytes,
            kind: SectionKind::Text,
        };
        let data = ImageSection {
            address: 0x2000,
            data: &data_bytes,
            kind: SectionKind::Data,
        };

        let function = decode_function(
            text,
            &[text, data],
            0x1000,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();

        assert_eq!(function.bytes, text_bytes[..8]);
        assert_eq!(instruction_offsets(&function), [0, 2]);
    }

    #[test]
    fn follows_near_lower_return_tail_block() {
        #[rustfmt::skip]
        let bytes = [
            0x8D, 0x42, 0xFF, // lea eax, [edx-1]
            0x5B,             // pop ebx
            0xC3,             // ret
            0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC,
            0x75, 0xEE,       // jne 0x1000
            0x31, 0xC0,       // xor eax, eax
            0xC3,             // ret
        ];
        let text = ImageSection {
            address: 0x1000,
            data: &bytes,
            kind: SectionKind::Text,
        };
        let function_starts = BTreeSet::from([0x1010]);

        let function =
            decode_function(text, &[text], 0x1010, &function_starts, &BTreeSet::new()).unwrap();
        let instruction_vas = function
            .instructions
            .iter()
            .map(|instruction| instruction.va)
            .collect::<Vec<_>>();

        assert_eq!(function.bytes, bytes[0x10..]);
        assert_eq!(
            instruction_vas,
            [0x1000, 0x1003, 0x1004, 0x1010, 0x1012, 0x1014]
        );
    }

    #[test]
    fn rejects_non_contiguous_functions_for_object_extraction() {
        let function = FunctionImage {
            va: 0x1010,
            bytes: vec![0x75, 0xEE, 0xC3],
            instructions: vec![DecodedInstruction {
                va: 0x1000,
                len: 1,
                text: "RET".to_owned(),
                branch: None,
            }],
        };

        assert!(!function_is_extractable(&function));
    }

    #[test]
    fn rejects_external_short_branches_for_object_extraction() {
        let function = FunctionImage {
            va: 0x1000,
            bytes: vec![0x75, 0xFE],
            instructions: vec![DecodedInstruction {
                va: 0x1000,
                len: 2,
                text: "JNZ 0xff0".to_owned(),
                branch: Some(BranchReference {
                    kind: DirectBranchKind::ConditionalBranch,
                    target: 0x0FF0,
                    operand_offset: 1,
                    operand_size: 1,
                }),
            }],
        };

        assert!(!function_is_extractable(&function));
    }

    #[test]
    fn accepts_external_near_branches_for_object_extraction() {
        let function = FunctionImage {
            va: 0x1000,
            bytes: vec![0xE8, 0, 0, 0, 0],
            instructions: vec![DecodedInstruction {
                va: 0x1000,
                len: 5,
                text: "CALL 0x2000".to_owned(),
                branch: Some(BranchReference {
                    kind: DirectBranchKind::Call,
                    target: 0x2000,
                    operand_offset: 1,
                    operand_size: 4,
                }),
            }],
        };

        assert!(function_is_extractable(&function));
    }

    fn decode_test_function(bytes: &[u8]) -> Result<FunctionImage> {
        decode_test_function_with_context(bytes, &[], &[])
    }

    fn decode_test_function_with_starts(
        bytes: &[u8],
        function_starts: &[u64],
    ) -> Result<FunctionImage> {
        decode_test_function_with_context(bytes, function_starts, &[])
    }

    fn decode_test_function_with_no_return_imports(
        bytes: &[u8],
        no_return_imports: &[u64],
    ) -> Result<FunctionImage> {
        decode_test_function_with_context(bytes, &[], no_return_imports)
    }

    fn decode_test_function_with_context(
        bytes: &[u8],
        function_starts: &[u64],
        no_return_imports: &[u64],
    ) -> Result<FunctionImage> {
        let section = ImageSection {
            address: 0x1000,
            data: bytes,
            kind: SectionKind::Text,
        };
        decode_function(
            section,
            &[section],
            0x1000,
            &function_starts.iter().copied().collect(),
            &no_return_imports.iter().copied().collect(),
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
