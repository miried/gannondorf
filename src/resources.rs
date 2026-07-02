use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use object::endian::LittleEndian as LE;
use object::pe;
use object::read::FileKind;
use object::read::pe::{
    ImageNtHeaders, PeFile, PeFile32, PeFile64, ResourceDirectory, ResourceDirectoryEntryData,
    ResourceDirectoryTable, ResourceNameOrId,
};

use crate::{Result, UnlinkError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedResources {
    pub rc_text: String,
    pub assets: Vec<ResourceAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAsset {
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceKey {
    Id(u16),
    Name(String),
}

#[derive(Debug, Clone)]
struct ResourceLeaf<'data> {
    typ: ResourceKey,
    name: ResourceKey,
    language: u16,
    data: &'data [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IconFileKind {
    Icon,
    Cursor,
}

#[derive(Debug, Clone, Copy)]
struct GroupEntry {
    id: u16,
    directory_prefix: [u8; 8],
}

type ResourceImageKey = (u16, u16);
type BuiltIconFile = (Vec<u8>, Vec<ResourceImageKey>);

struct ResourceRenderer {
    rc_text: String,
    assets: Vec<ResourceAsset>,
    asset_prefix: String,
    used_asset_names: BTreeSet<String>,
    current_language: Option<u16>,
}

pub fn extract_resource_script(image: &[u8], asset_dir_name: &str) -> Result<ExtractedResources> {
    match FileKind::parse(image)
        .map_err(|err| UnlinkError::new(format!("failed to identify input file: {err}")))?
    {
        FileKind::Pe32 => {
            let file = PeFile32::parse(image)
                .map_err(|err| UnlinkError::new(format!("failed to parse PE32 image: {err}")))?;
            extract_pe_resource_script(&file, asset_dir_name)
        }
        FileKind::Pe64 => {
            let file = PeFile64::parse(image)
                .map_err(|err| UnlinkError::new(format!("failed to parse PE32+ image: {err}")))?;
            extract_pe_resource_script(&file, asset_dir_name)
        }
        kind => Err(UnlinkError::new(format!(
            "unsupported input file kind {kind:?}; only PE32 and PE32+ resources are implemented"
        ))),
    }
}

fn extract_pe_resource_script<Pe>(
    file: &PeFile<'_, Pe>,
    asset_dir_name: &str,
) -> Result<ExtractedResources>
where
    Pe: ImageNtHeaders,
{
    let Some(directory) = file
        .data_directories()
        .resource_directory(file.data(), &file.section_table())
        .map_err(|err| UnlinkError::new(format!("failed to read PE resources: {err}")))?
    else {
        return Ok(ExtractedResources {
            rc_text: String::new(),
            assets: Vec::new(),
        });
    };

    let root = directory
        .root()
        .map_err(|err| UnlinkError::new(format!("failed to parse PE resource root: {err}")))?;
    let leaves = collect_resource_leaves(file, directory, &root)?;
    render_resource_script(&leaves, asset_dir_name)
}

fn collect_resource_leaves<'data, Pe>(
    file: &PeFile<'data, Pe>,
    directory: ResourceDirectory<'data>,
    root: &ResourceDirectoryTable<'data>,
) -> Result<Vec<ResourceLeaf<'data>>>
where
    Pe: ImageNtHeaders,
{
    let mut leaves = Vec::new();
    for type_entry in root.entries {
        let typ = resource_key(type_entry.name_or_id(), directory)?;
        let name_table = entry_table(type_entry, directory, "resource type")?;
        for name_entry in name_table.entries {
            let name = resource_key(name_entry.name_or_id(), directory)?;
            let language_table = entry_table(name_entry, directory, "resource name")?;
            for language_entry in language_table.entries {
                let language = resource_language_id(language_entry.name_or_id(), directory)?;
                let data_entry = entry_data(language_entry, directory, "resource language")?;
                let data = resource_data(file, data_entry)?;
                leaves.push(ResourceLeaf {
                    typ: typ.clone(),
                    name: name.clone(),
                    language,
                    data,
                });
            }
        }
    }

    leaves.sort_by(|left, right| {
        (&left.typ, &left.name, left.language).cmp(&(&right.typ, &right.name, right.language))
    });
    Ok(leaves)
}

fn resource_key(
    name_or_id: ResourceNameOrId,
    directory: ResourceDirectory<'_>,
) -> Result<ResourceKey> {
    match name_or_id {
        ResourceNameOrId::Id(id) => Ok(ResourceKey::Id(id)),
        ResourceNameOrId::Name(name) => name
            .to_string_lossy(directory)
            .map(ResourceKey::Name)
            .map_err(|err| UnlinkError::new(format!("failed to decode resource name: {err}"))),
    }
}

fn resource_language_id(
    name_or_id: ResourceNameOrId,
    directory: ResourceDirectory<'_>,
) -> Result<u16> {
    match resource_key(name_or_id, directory)? {
        ResourceKey::Id(id) => Ok(id),
        ResourceKey::Name(name) => Err(UnlinkError::new(format!(
            "unsupported named resource language `{name}`"
        ))),
    }
}

fn entry_table<'data>(
    entry: &pe::ImageResourceDirectoryEntry,
    directory: ResourceDirectory<'data>,
    context: &str,
) -> Result<ResourceDirectoryTable<'data>> {
    match entry
        .data(directory)
        .map_err(|err| UnlinkError::new(format!("failed to read {context} table: {err}")))?
    {
        ResourceDirectoryEntryData::Table(table) => Ok(table),
        ResourceDirectoryEntryData::Data(_) => Err(UnlinkError::new(format!(
            "malformed PE resources: {context} entry points directly to data"
        ))),
    }
}

fn entry_data<'data>(
    entry: &pe::ImageResourceDirectoryEntry,
    directory: ResourceDirectory<'data>,
    context: &str,
) -> Result<&'data pe::ImageResourceDataEntry> {
    match entry
        .data(directory)
        .map_err(|err| UnlinkError::new(format!("failed to read {context} data: {err}")))?
    {
        ResourceDirectoryEntryData::Data(data) => Ok(data),
        ResourceDirectoryEntryData::Table(_) => Err(UnlinkError::new(format!(
            "malformed PE resources: {context} entry points to another table"
        ))),
    }
}

fn resource_data<'data, Pe>(
    file: &PeFile<'data, Pe>,
    data_entry: &pe::ImageResourceDataEntry,
) -> Result<&'data [u8]>
where
    Pe: ImageNtHeaders,
{
    let rva = data_entry.offset_to_data.get(LE);
    let size = data_entry.size.get(LE) as usize;
    file.section_table()
        .pe_data_at(file.data(), rva)
        .and_then(|bytes| bytes.get(..size))
        .ok_or_else(|| {
            UnlinkError::new(format!(
                "resource data at RVA 0x{rva:08X} with size 0x{size:X} is outside section data"
            ))
        })
}

fn render_resource_script(
    leaves: &[ResourceLeaf<'_>],
    asset_dir_name: &str,
) -> Result<ExtractedResources> {
    let mut renderer = ResourceRenderer::new(asset_dir_name);
    let image_resources = collect_numeric_resources(leaves, pe::RT_ICON);
    let cursor_resources = collect_numeric_resources(leaves, pe::RT_CURSOR);
    let mut handled = BTreeSet::new();
    let mut consumed_images = BTreeSet::new();
    let mut consumed_cursors = BTreeSet::new();

    for (index, leaf) in leaves.iter().enumerate() {
        if leaf.typ == ResourceKey::Id(pe::RT_STRING)
            && renderer.try_render_string_table(leaf).unwrap_or(false)
        {
            handled.insert(index);
        }
    }

    for (index, leaf) in leaves.iter().enumerate() {
        match leaf.typ {
            ResourceKey::Id(pe::RT_GROUP_ICON) => {
                match build_icon_file(leaf, IconFileKind::Icon, &image_resources) {
                    Ok((bytes, image_ids)) => {
                        renderer.render_icon_or_cursor(leaf, IconFileKind::Icon, bytes)?;
                        handled.insert(index);
                        consumed_images.extend(image_ids);
                    }
                    Err(_) => {
                        renderer.render_raw_resource(leaf)?;
                        handled.insert(index);
                    }
                }
            }
            ResourceKey::Id(pe::RT_GROUP_CURSOR) => {
                match build_icon_file(leaf, IconFileKind::Cursor, &cursor_resources) {
                    Ok((bytes, cursor_ids)) => {
                        renderer.render_icon_or_cursor(leaf, IconFileKind::Cursor, bytes)?;
                        handled.insert(index);
                        consumed_cursors.extend(cursor_ids);
                    }
                    Err(_) => {
                        renderer.render_raw_resource(leaf)?;
                        handled.insert(index);
                    }
                }
            }
            _ => {}
        }
    }

    for (index, leaf) in leaves.iter().enumerate() {
        if handled.contains(&index) {
            continue;
        }
        match leaf.typ {
            ResourceKey::Id(pe::RT_ICON)
                if numeric_name(&leaf.name)
                    .is_some_and(|id| consumed_images.contains(&(leaf.language, id))) =>
            {
                continue;
            }
            ResourceKey::Id(pe::RT_CURSOR)
                if numeric_name(&leaf.name)
                    .is_some_and(|id| consumed_cursors.contains(&(leaf.language, id))) =>
            {
                continue;
            }
            ResourceKey::Id(pe::RT_STRING) if handled.contains(&index) => continue,
            ResourceKey::Id(pe::RT_MENU) => match render_menu_resource(leaf) {
                Ok(text) => renderer.render_text_resource(leaf.language, &text),
                Err(_) => renderer.render_raw_resource(leaf)?,
            },
            ResourceKey::Id(pe::RT_DIALOG) => match render_dialog_resource(leaf) {
                Ok(text) => renderer.render_text_resource(leaf.language, &text),
                Err(_) => renderer.render_raw_resource(leaf)?,
            },
            ResourceKey::Id(pe::RT_ACCELERATOR) => match render_accelerator_resource(leaf) {
                Ok(text) => renderer.render_text_resource(leaf.language, &text),
                Err(_) => renderer.render_raw_resource(leaf)?,
            },
            _ => renderer.render_raw_resource(leaf)?,
        }
    }

    Ok(renderer.finish())
}

fn collect_numeric_resources<'data>(
    leaves: &'data [ResourceLeaf<'data>],
    resource_type: u16,
) -> BTreeMap<(u16, u16), &'data [u8]> {
    leaves
        .iter()
        .filter_map(|leaf| {
            if leaf.typ != ResourceKey::Id(resource_type) {
                return None;
            }
            numeric_name(&leaf.name).map(|name| ((leaf.language, name), leaf.data))
        })
        .collect()
}

fn numeric_name(name: &ResourceKey) -> Option<u16> {
    match name {
        ResourceKey::Id(id) => Some(*id),
        ResourceKey::Name(_) => None,
    }
}

impl ResourceRenderer {
    fn new(asset_dir_name: &str) -> Self {
        Self {
            rc_text: String::new(),
            assets: Vec::new(),
            asset_prefix: normalize_rc_path(asset_dir_name),
            used_asset_names: BTreeSet::new(),
            current_language: None,
        }
    }

    fn finish(self) -> ExtractedResources {
        ExtractedResources {
            rc_text: self.rc_text,
            assets: self.assets,
        }
    }

    fn try_render_string_table(&mut self, leaf: &ResourceLeaf<'_>) -> Result<bool> {
        let Some(block_id) = numeric_name(&leaf.name) else {
            return Ok(false);
        };
        if block_id == 0 {
            return Ok(false);
        }

        let strings = parse_string_table_block(leaf.data)?;
        if strings.iter().all(Option::is_none) {
            return Ok(true);
        }

        self.write_language(leaf.language);
        self.rc_text.push_str("STRINGTABLE\nBEGIN\n");
        let base_id = (u32::from(block_id) - 1) * 16;
        for (index, string) in strings.iter().enumerate() {
            let Some(string) = string else {
                continue;
            };
            let string_id = base_id + index as u32;
            self.rc_text.push_str(&format!(
                "    {string_id} \"{}\"\n",
                escape_rc_utf16_string(string)
            ));
        }
        self.rc_text.push_str("END\n\n");
        Ok(true)
    }

    fn render_icon_or_cursor(
        &mut self,
        leaf: &ResourceLeaf<'_>,
        kind: IconFileKind,
        bytes: Vec<u8>,
    ) -> Result<()> {
        self.write_language(leaf.language);
        let extension = match kind {
            IconFileKind::Icon => "ico",
            IconFileKind::Cursor => "cur",
        };
        let keyword = match kind {
            IconFileKind::Icon => "ICON",
            IconFileKind::Cursor => "CURSOR",
        };
        let file_name = format!(
            "{}_{}_lang_{:04X}.{extension}",
            keyword.to_ascii_lowercase(),
            resource_key_token(&leaf.name),
            leaf.language
        );
        let path = self.add_asset(file_name, bytes);
        self.rc_text.push_str(&format!(
            "{} {keyword} \"{}\"\n\n",
            rc_resource_key(&leaf.name),
            escape_rc_text(&path)
        ));
        Ok(())
    }

    fn render_raw_resource(&mut self, leaf: &ResourceLeaf<'_>) -> Result<()> {
        self.write_language(leaf.language);
        let file_name = format!(
            "resource_type_{}_name_{}_lang_{:04X}.bin",
            resource_key_token(&leaf.typ),
            resource_key_token(&leaf.name),
            leaf.language
        );
        let path = self.add_asset(file_name, leaf.data.to_vec());
        self.rc_text.push_str(&format!(
            "{} {} \"{}\"\n\n",
            rc_resource_key(&leaf.name),
            rc_resource_key(&leaf.typ),
            escape_rc_text(&path)
        ));
        Ok(())
    }

    fn render_text_resource(&mut self, language: u16, text: &str) {
        self.write_language(language);
        self.rc_text.push_str(text);
    }

    fn write_language(&mut self, language: u16) {
        if self.current_language == Some(language) {
            return;
        }
        let primary_language = language & 0x03FF;
        let sublanguage = language >> 10;
        self.rc_text
            .push_str(&format!("LANGUAGE {primary_language}, {sublanguage}\n"));
        self.current_language = Some(language);
    }

    fn add_asset(&mut self, file_name: String, bytes: Vec<u8>) -> String {
        let file_name = self.unique_file_name(file_name);
        let path = if self.asset_prefix.is_empty() || self.asset_prefix == "." {
            file_name
        } else {
            format!("{}/{}", self.asset_prefix.trim_end_matches('/'), file_name)
        };
        self.assets.push(ResourceAsset {
            relative_path: path.clone(),
            bytes,
        });
        path
    }

    fn unique_file_name(&mut self, file_name: String) -> String {
        if self.used_asset_names.insert(file_name.clone()) {
            return file_name;
        }

        let (stem, extension) = file_name
            .rsplit_once('.')
            .map_or((file_name.as_str(), ""), |(stem, extension)| {
                (stem, extension)
            });
        for suffix in 2.. {
            let candidate = if extension.is_empty() {
                format!("{stem}_{suffix}")
            } else {
                format!("{stem}_{suffix}.{extension}")
            };
            if self.used_asset_names.insert(candidate.clone()) {
                return candidate;
            }
        }
        unreachable!("unbounded suffix search must find a file name");
    }
}

fn build_icon_file(
    group: &ResourceLeaf<'_>,
    kind: IconFileKind,
    images: &BTreeMap<ResourceImageKey, &[u8]>,
) -> Result<BuiltIconFile> {
    let entries = parse_group_entries(group.data, kind)?;
    let mut output = Vec::new();
    write_u16(&mut output, 0);
    write_u16(
        &mut output,
        match kind {
            IconFileKind::Icon => 1,
            IconFileKind::Cursor => 2,
        },
    );
    write_u16(&mut output, entries.len() as u16);

    let directory_size = 6 + entries.len() * 16;
    let mut image_offset = directory_size as u32;
    let mut payloads = Vec::new();
    let mut consumed = Vec::new();
    for entry in &entries {
        let resource = images
            .get(&(group.language, entry.id))
            .ok_or_else(|| UnlinkError::new("group resource references a missing image"))?;
        let (directory_prefix, payload) = match kind {
            IconFileKind::Icon => (entry.directory_prefix, (*resource).to_vec()),
            IconFileKind::Cursor => {
                let (hotspot, payload) = cursor_payload_for_cur_file(resource)?;
                let mut directory_prefix = entry.directory_prefix;
                directory_prefix[4..8].copy_from_slice(&hotspot);
                (directory_prefix, payload)
            }
        };
        let payload_size = payload.len() as u32;

        output.extend_from_slice(&directory_prefix);
        write_u32(&mut output, payload_size);
        write_u32(&mut output, image_offset);
        image_offset = image_offset
            .checked_add(payload_size)
            .ok_or_else(|| UnlinkError::new("icon/cursor file offsets overflowed"))?;
        payloads.push(payload);
        consumed.push((group.language, entry.id));
    }

    for payload in payloads {
        output.extend_from_slice(&payload);
    }
    Ok((output, consumed))
}

fn parse_group_entries(data: &[u8], kind: IconFileKind) -> Result<Vec<GroupEntry>> {
    if data.len() < 6 {
        return Err(UnlinkError::new(
            "group resource is shorter than its header",
        ));
    }
    if read_u16_at(data, 0)? != 0 {
        return Err(UnlinkError::new(
            "group resource reserved field is non-zero",
        ));
    }
    let expected_type = match kind {
        IconFileKind::Icon => 1,
        IconFileKind::Cursor => 2,
    };
    if read_u16_at(data, 2)? != expected_type {
        return Err(UnlinkError::new("group resource has an unexpected type"));
    }

    let count = read_u16_at(data, 4)? as usize;
    let expected_len = 6usize
        .checked_add(
            count
                .checked_mul(14)
                .ok_or_else(|| UnlinkError::new("group resource entry count overflowed"))?,
        )
        .ok_or_else(|| UnlinkError::new("group resource size overflowed"))?;
    if data.len() < expected_len {
        return Err(UnlinkError::new(
            "group resource is shorter than its entry table",
        ));
    }

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 6 + index * 14;
        let mut directory_prefix = [0u8; 8];
        match kind {
            IconFileKind::Icon => {
                directory_prefix.copy_from_slice(&data[offset..offset + 8]);
            }
            IconFileKind::Cursor => {
                let width = read_u16_at(data, offset)?;
                let height = read_u16_at(data, offset + 2)?;
                directory_prefix[0] = ico_dimension(width);
                directory_prefix[1] = ico_dimension(height / 2);
                directory_prefix[2] = 0;
                directory_prefix[3] = 0;
            }
        }
        entries.push(GroupEntry {
            id: read_u16_at(data, offset + 12)?,
            directory_prefix,
        });
    }
    Ok(entries)
}

fn cursor_payload_for_cur_file(resource: &[u8]) -> Result<([u8; 4], Vec<u8>)> {
    if resource.len() < 4 {
        return Err(UnlinkError::new(
            "cursor resource is shorter than its hotspot",
        ));
    }
    let mut hotspot = [0u8; 4];
    hotspot.copy_from_slice(&resource[..4]);
    Ok((hotspot, resource[4..].to_vec()))
}

fn parse_string_table_block(data: &[u8]) -> Result<Vec<Option<Vec<u16>>>> {
    let mut strings = Vec::with_capacity(16);
    let mut offset = 0usize;
    for _ in 0..16 {
        let len = read_u16_at(data, offset)? as usize;
        offset += 2;
        let byte_len = len
            .checked_mul(2)
            .ok_or_else(|| UnlinkError::new("string table entry length overflowed"))?;
        let end = offset
            .checked_add(byte_len)
            .ok_or_else(|| UnlinkError::new("string table entry end overflowed"))?;
        let bytes = data
            .get(offset..end)
            .ok_or_else(|| UnlinkError::new("string table entry extends past resource data"))?;
        if len == 0 {
            strings.push(None);
        } else {
            strings.push(Some(
                bytes
                    .chunks_exact(2)
                    .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                    .collect(),
            ));
        }
        offset = end;
    }
    Ok(strings)
}

fn read_u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| UnlinkError::new("unexpected end of resource data"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn ico_dimension(value: u16) -> u8 {
    match value {
        0 | 256 => 0,
        1..=255 => value as u8,
        _ => 0,
    }
}

fn rc_resource_key(key: &ResourceKey) -> String {
    match key {
        ResourceKey::Id(id) => id.to_string(),
        ResourceKey::Name(name) if is_rc_identifier(name) => name.clone(),
        ResourceKey::Name(name) => format!("\"{}\"", escape_rc_text(name)),
    }
}

fn is_rc_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    is_rc_identifier_start(first) && chars.all(is_rc_identifier_continue)
}

fn is_rc_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_rc_identifier_continue(ch: char) -> bool {
    is_rc_identifier_start(ch) || ch.is_ascii_digit() || ch == '.'
}

fn resource_key_token(key: &ResourceKey) -> String {
    match key {
        ResourceKey::Id(id) => format!("id_{id:04X}"),
        ResourceKey::Name(name) => format!("name_{}", sanitize_file_token(name)),
    }
}

fn sanitize_file_token(input: &str) -> String {
    let mut output = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch);
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    let output = output.trim_matches('_');
    if output.is_empty() {
        "resource".to_owned()
    } else {
        output.to_owned()
    }
}

fn normalize_rc_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn escape_rc_text(input: &str) -> String {
    escape_rc_utf16_string(&input.encode_utf16().collect::<Vec<_>>())
}

fn escape_rc_utf16_string(units: &[u16]) -> String {
    let mut output = String::new();
    for &unit in units {
        match unit {
            0x0A => output.push_str("\\n"),
            0x0D => output.push_str("\\r"),
            0x09 => output.push_str("\\t"),
            0x22 => output.push_str("\"\""),
            0x5C => output.push_str("\\\\"),
            0x20..=0x7E => output.push(char::from_u32(u32::from(unit)).expect("valid ASCII")),
            _ => output.push_str(&format!("\\x{unit:04X}")),
        }
    }
    output
}

impl fmt::Debug for ResourceRenderer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceRenderer")
            .field("rc_text", &self.rc_text)
            .field("assets", &self.assets)
            .field("asset_prefix", &self.asset_prefix)
            .field("current_language", &self.current_language)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct MenuItem {
    flags: u16,
    id: Option<u16>,
    text: Vec<u16>,
    children: Vec<MenuItem>,
}

#[derive(Debug, Clone)]
struct DialogTemplate {
    style: u32,
    extended_style: u32,
    x: i16,
    y: i16,
    cx: i16,
    cy: i16,
    menu: DialogValue,
    class: DialogValue,
    title: DialogValue,
    font: Option<DialogFont>,
    controls: Vec<DialogControl>,
}

#[derive(Debug, Clone)]
struct DialogFont {
    point_size: u16,
    face: Vec<u16>,
}

#[derive(Debug, Clone)]
struct DialogControl {
    style: u32,
    extended_style: u32,
    x: i16,
    y: i16,
    cx: i16,
    cy: i16,
    id: u16,
    class: DialogValue,
    title: DialogValue,
}

#[derive(Debug, Clone)]
enum DialogValue {
    None,
    Ordinal(u16),
    String(Vec<u16>),
}

const MENU_GRAYED: u16 = 0x0001;
const MENU_INACTIVE: u16 = 0x0002;
const MENU_BITMAP: u16 = 0x0004;
const MENU_CHECKED: u16 = 0x0008;
const MENU_POPUP: u16 = 0x0010;
const MENU_MENUBARBREAK: u16 = 0x0020;
const MENU_MENUBREAK: u16 = 0x0040;
const MENU_END: u16 = 0x0080;
const MENU_OWNERDRAW: u16 = 0x0100;
const MENU_SEPARATOR: u16 = 0x0800;
const MENU_HELP: u16 = 0x4000;

const DS_SETFONT: u32 = 0x0000_0040;

const ACCEL_VIRTKEY: u16 = 0x0001;
const ACCEL_NOINVERT: u16 = 0x0002;
const ACCEL_SHIFT: u16 = 0x0004;
const ACCEL_CONTROL: u16 = 0x0008;
const ACCEL_ALT: u16 = 0x0010;
const ACCEL_LAST: u16 = 0x0080;

fn render_menu_resource(leaf: &ResourceLeaf<'_>) -> Result<String> {
    let data = leaf.data;
    if read_u16_at(data, 0)? != 0 {
        return Err(UnlinkError::new("extended menus are not implemented"));
    }
    let header_size = read_u16_at(data, 2)? as usize;
    let mut offset = 4usize
        .checked_add(header_size)
        .ok_or_else(|| UnlinkError::new("menu header size overflowed"))?;
    if offset > data.len() {
        return Err(UnlinkError::new("menu header extends past resource data"));
    }

    let items = parse_menu_items(data, &mut offset)?;
    reject_nonzero_trailing_data(data, offset, "menu")?;

    let mut output = format!("{} MENU\nBEGIN\n", rc_resource_key(&leaf.name));
    render_menu_items(&mut output, &items, 1)?;
    output.push_str("END\n\n");
    Ok(output)
}

fn parse_menu_items(data: &[u8], offset: &mut usize) -> Result<Vec<MenuItem>> {
    let mut items = Vec::new();
    loop {
        if *offset >= data.len() {
            return Err(UnlinkError::new("menu item list is missing an end marker"));
        }

        let flags = read_u16_at(data, *offset)?;
        *offset += 2;
        let is_popup = flags & MENU_POPUP != 0;
        let (id, text, children) = if is_popup {
            let text = read_utf16z(data, offset)?;
            let children = parse_menu_items(data, offset)?;
            (None, text, children)
        } else {
            let id = read_u16_at(data, *offset)?;
            *offset += 2;
            let text = read_utf16z(data, offset)?;
            (Some(id), text, Vec::new())
        };
        let is_end = flags & MENU_END != 0;
        items.push(MenuItem {
            flags,
            id,
            text,
            children,
        });
        if is_end {
            break;
        }
    }
    Ok(items)
}

fn render_menu_items(output: &mut String, items: &[MenuItem], indent: usize) -> Result<()> {
    for item in items {
        render_menu_item(output, item, indent)?;
    }
    Ok(())
}

fn render_menu_item(output: &mut String, item: &MenuItem, indent: usize) -> Result<()> {
    let indent_text = "    ".repeat(indent);
    if item.flags & MENU_POPUP != 0 {
        output.push_str(&format!(
            "{indent_text}POPUP \"{}\"{}\n{indent_text}BEGIN\n",
            escape_rc_utf16_string(&item.text),
            menu_option_suffix(item.flags & !(MENU_POPUP | MENU_END | MENU_SEPARATOR))?
        ));
        render_menu_items(output, &item.children, indent + 1)?;
        output.push_str(&format!("{indent_text}END\n"));
        return Ok(());
    }

    let id = item
        .id
        .ok_or_else(|| UnlinkError::new("non-popup menu item is missing an id"))?;
    if item.flags & MENU_SEPARATOR != 0 {
        if id != 0 || !item.text.is_empty() {
            return Err(UnlinkError::new(
                "separator menu item has unexpected id or text",
            ));
        }
        output.push_str(&format!("{indent_text}MENUITEM SEPARATOR\n"));
        return Ok(());
    }

    output.push_str(&format!(
        "{indent_text}MENUITEM \"{}\", {}{}\n",
        escape_rc_utf16_string(&item.text),
        id,
        menu_option_suffix(item.flags & !MENU_END)?
    ));
    Ok(())
}

fn menu_option_suffix(flags: u16) -> Result<String> {
    if flags & (MENU_BITMAP | MENU_OWNERDRAW) != 0 {
        return Err(UnlinkError::new(
            "bitmap and owner-drawn menu items are not implemented",
        ));
    }

    let mut options = Vec::new();
    push_flag_option(flags, MENU_GRAYED, "GRAYED", &mut options);
    push_flag_option(flags, MENU_INACTIVE, "INACTIVE", &mut options);
    push_flag_option(flags, MENU_CHECKED, "CHECKED", &mut options);
    push_flag_option(flags, MENU_MENUBARBREAK, "MENUBARBREAK", &mut options);
    push_flag_option(flags, MENU_MENUBREAK, "MENUBREAK", &mut options);
    push_flag_option(flags, MENU_HELP, "HELP", &mut options);

    let known =
        MENU_GRAYED | MENU_INACTIVE | MENU_CHECKED | MENU_MENUBARBREAK | MENU_MENUBREAK | MENU_HELP;
    let unknown = flags & !known;
    if unknown != 0 {
        return Err(UnlinkError::new(format!(
            "unsupported menu option flags 0x{unknown:04X}"
        )));
    }

    if options.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!(", {}", options.join(", ")))
    }
}

fn render_dialog_resource(leaf: &ResourceLeaf<'_>) -> Result<String> {
    let dialog = parse_dialog_template(leaf.data)?;
    let mut output = format!(
        "{} DIALOG {}, {}, {}, {}\n",
        rc_resource_key(&leaf.name),
        dialog.x,
        dialog.y,
        dialog.cx,
        dialog.cy
    );
    output.push_str(&format!("STYLE 0x{:08X}\n", dialog.style));
    if dialog.extended_style != 0 {
        output.push_str(&format!("EXSTYLE 0x{:08X}\n", dialog.extended_style));
    }
    if let Some(menu) = dialog_directive_value(&dialog.menu)? {
        output.push_str(&format!("MENU {menu}\n"));
    }
    if let Some(class) = dialog_directive_value(&dialog.class)? {
        output.push_str(&format!("CLASS {class}\n"));
    }
    if let Some(caption) = dialog_directive_value(&dialog.title)? {
        output.push_str(&format!("CAPTION {caption}\n"));
    }
    if let Some(font) = &dialog.font {
        output.push_str(&format!(
            "FONT {}, \"{}\"\n",
            font.point_size,
            escape_rc_utf16_string(&font.face)
        ));
    }
    output.push_str("BEGIN\n");
    for control in &dialog.controls {
        render_dialog_control(&mut output, control)?;
    }
    output.push_str("END\n\n");
    Ok(output)
}

fn parse_dialog_template(data: &[u8]) -> Result<DialogTemplate> {
    if read_u16_at(data, 0)? == 1 && read_u16_at(data, 2)? == 0xFFFF {
        return Err(UnlinkError::new("DIALOGEX resources are not implemented"));
    }

    let style = read_u32_at(data, 0)?;
    let extended_style = read_u32_at(data, 4)?;
    let control_count = read_u16_at(data, 8)? as usize;
    let x = read_i16_at(data, 10)?;
    let y = read_i16_at(data, 12)?;
    let cx = read_i16_at(data, 14)?;
    let cy = read_i16_at(data, 16)?;
    let mut offset = 18usize;

    let menu = read_dialog_value(data, &mut offset)?;
    let class = read_dialog_value(data, &mut offset)?;
    let title = read_dialog_value(data, &mut offset)?;
    let font = if style & DS_SETFONT != 0 {
        let point_size = read_u16_at(data, offset)?;
        offset += 2;
        Some(DialogFont {
            point_size,
            face: read_utf16z(data, &mut offset)?,
        })
    } else {
        None
    };

    let mut controls = Vec::with_capacity(control_count);
    for _ in 0..control_count {
        align_offset(data, &mut offset)?;
        let style = read_u32_at(data, offset)?;
        let extended_style = read_u32_at(data, offset + 4)?;
        let x = read_i16_at(data, offset + 8)?;
        let y = read_i16_at(data, offset + 10)?;
        let cx = read_i16_at(data, offset + 12)?;
        let cy = read_i16_at(data, offset + 14)?;
        let id = read_u16_at(data, offset + 16)?;
        offset += 18;

        let class = read_dialog_value(data, &mut offset)?;
        let title = read_dialog_value(data, &mut offset)?;
        let extra_size = read_u16_at(data, offset)? as usize;
        offset += 2;
        let extra_end = offset
            .checked_add(extra_size)
            .ok_or_else(|| UnlinkError::new("dialog control extra data size overflowed"))?;
        let extra = data
            .get(offset..extra_end)
            .ok_or_else(|| UnlinkError::new("dialog control extra data extends past resource"))?;
        if !extra.is_empty() {
            return Err(UnlinkError::new(
                "dialog control creation data is not implemented",
            ));
        }
        offset = extra_end;

        controls.push(DialogControl {
            style,
            extended_style,
            x,
            y,
            cx,
            cy,
            id,
            class,
            title,
        });
    }
    reject_nonzero_trailing_data(data, offset, "dialog")?;

    Ok(DialogTemplate {
        style,
        extended_style,
        x,
        y,
        cx,
        cy,
        menu,
        class,
        title,
        font,
        controls,
    })
}

fn render_dialog_control(output: &mut String, control: &DialogControl) -> Result<()> {
    output.push_str(&format!(
        "    CONTROL {}, {}, {}, 0x{:08X}, {}, {}, {}, {}",
        dialog_control_title(&control.title)?,
        control.id,
        dialog_control_class(&control.class)?,
        control.style,
        control.x,
        control.y,
        control.cx,
        control.cy
    ));
    if control.extended_style != 0 {
        output.push_str(&format!(", 0x{:08X}", control.extended_style));
    }
    output.push('\n');
    Ok(())
}

fn render_accelerator_resource(leaf: &ResourceLeaf<'_>) -> Result<String> {
    if !leaf.data.len().is_multiple_of(8) {
        return Err(UnlinkError::new(
            "accelerator resource size is not a multiple of entry size",
        ));
    }

    let mut output = format!("{} ACCELERATORS\nBEGIN\n", rc_resource_key(&leaf.name));
    let entry_count = leaf.data.len() / 8;
    for index in 0..entry_count {
        let offset = index * 8;
        let flags = read_u16_at(leaf.data, offset)?;
        let key = read_u16_at(leaf.data, offset + 2)?;
        let id = read_u16_at(leaf.data, offset + 4)?;
        let padding = read_u16_at(leaf.data, offset + 6)?;
        if padding != 0 {
            return Err(UnlinkError::new("accelerator padding is non-zero"));
        }
        if (flags & ACCEL_LAST != 0) != (index + 1 == entry_count) {
            return Err(UnlinkError::new(
                "accelerator last-entry marker is not on the final entry",
            ));
        }
        output.push_str(&format!(
            "    {}, {}, {}\n",
            key,
            id,
            accelerator_options(flags & !ACCEL_LAST)?
        ));
    }
    output.push_str("END\n\n");
    Ok(output)
}

fn accelerator_options(flags: u16) -> Result<String> {
    let mut options = Vec::new();
    if flags & ACCEL_VIRTKEY != 0 {
        options.push("VIRTKEY");
    } else {
        options.push("ASCII");
    }
    push_flag_option(flags, ACCEL_NOINVERT, "NOINVERT", &mut options);
    push_flag_option(flags, ACCEL_SHIFT, "SHIFT", &mut options);
    push_flag_option(flags, ACCEL_CONTROL, "CONTROL", &mut options);
    push_flag_option(flags, ACCEL_ALT, "ALT", &mut options);

    let known = ACCEL_VIRTKEY | ACCEL_NOINVERT | ACCEL_SHIFT | ACCEL_CONTROL | ACCEL_ALT;
    let unknown = flags & !known;
    if unknown != 0 {
        return Err(UnlinkError::new(format!(
            "unsupported accelerator flags 0x{unknown:04X}"
        )));
    }
    Ok(options.join(", "))
}

fn dialog_directive_value(value: &DialogValue) -> Result<Option<String>> {
    match value {
        DialogValue::None => Ok(None),
        DialogValue::Ordinal(id) => Ok(Some(id.to_string())),
        DialogValue::String(text) => Ok(Some(format!("\"{}\"", escape_rc_utf16_string(text)))),
    }
}

fn dialog_control_title(value: &DialogValue) -> Result<String> {
    match value {
        DialogValue::None => Ok("\"\"".to_owned()),
        DialogValue::Ordinal(id) => Ok(id.to_string()),
        DialogValue::String(text) => Ok(format!("\"{}\"", escape_rc_utf16_string(text))),
    }
}

fn dialog_control_class(value: &DialogValue) -> Result<String> {
    match value {
        DialogValue::None => Err(UnlinkError::new("dialog control is missing its class")),
        DialogValue::String(text) => Ok(format!("\"{}\"", escape_rc_utf16_string(text))),
        DialogValue::Ordinal(0x80) => Ok("\"BUTTON\"".to_owned()),
        DialogValue::Ordinal(0x81) => Ok("\"EDIT\"".to_owned()),
        DialogValue::Ordinal(0x82) => Ok("\"STATIC\"".to_owned()),
        DialogValue::Ordinal(0x83) => Ok("\"LISTBOX\"".to_owned()),
        DialogValue::Ordinal(0x84) => Ok("\"SCROLLBAR\"".to_owned()),
        DialogValue::Ordinal(0x85) => Ok("\"COMBOBOX\"".to_owned()),
        DialogValue::Ordinal(id) => Err(UnlinkError::new(format!(
            "unsupported dialog control class ordinal 0x{id:04X}"
        ))),
    }
}

fn read_dialog_value(data: &[u8], offset: &mut usize) -> Result<DialogValue> {
    let marker = read_u16_at(data, *offset)?;
    match marker {
        0x0000 => {
            *offset += 2;
            Ok(DialogValue::None)
        }
        0xFFFF => {
            *offset += 2;
            let id = read_u16_at(data, *offset)?;
            *offset += 2;
            Ok(DialogValue::Ordinal(id))
        }
        _ => read_utf16z(data, offset).map(DialogValue::String),
    }
}

fn read_utf16z(data: &[u8], offset: &mut usize) -> Result<Vec<u16>> {
    let mut units = Vec::new();
    loop {
        let unit = read_u16_at(data, *offset)?;
        *offset += 2;
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    Ok(units)
}

fn read_i16_at(data: &[u8], offset: usize) -> Result<i16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| UnlinkError::new("unexpected end of resource data"))?;
    Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| UnlinkError::new("unexpected end of resource data"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn align_offset(data: &[u8], offset: &mut usize) -> Result<()> {
    *offset = offset
        .checked_add(3)
        .ok_or_else(|| UnlinkError::new("resource offset overflowed"))?
        & !3;
    if *offset > data.len() {
        return Err(UnlinkError::new("resource alignment skipped past data"));
    }
    Ok(())
}

fn reject_nonzero_trailing_data(data: &[u8], offset: usize, context: &str) -> Result<()> {
    if data
        .get(offset..)
        .is_some_and(|tail| tail.iter().all(|&byte| byte == 0))
    {
        Ok(())
    } else {
        Err(UnlinkError::new(format!(
            "{context} resource has trailing non-zero data"
        )))
    }
}

fn push_flag_option<'a>(flags: u16, flag: u16, label: &'a str, options: &mut Vec<&'a str>) {
    if flags & flag != 0 {
        options.push(label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_string_table_blocks() {
        let mut data = Vec::new();
        for index in 0..16 {
            let text = match index {
                1 => "Hello",
                15 => "Tail",
                _ => "",
            };
            let units = text.encode_utf16().collect::<Vec<_>>();
            data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for unit in units {
                data.extend_from_slice(&unit.to_le_bytes());
            }
        }

        let strings = parse_string_table_block(&data).unwrap();

        assert_eq!(strings[0], None);
        assert_eq!(strings[1], Some("Hello".encode_utf16().collect::<Vec<_>>()));
        assert_eq!(strings[15], Some("Tail".encode_utf16().collect::<Vec<_>>()));
    }

    #[test]
    fn escapes_rc_string_units() {
        let units = [b'A' as u16, b'"' as u16, b'\\' as u16, b'\n' as u16, 0x263A];

        assert_eq!(escape_rc_utf16_string(&units), "A\"\"\\\\\\n\\x263A");
    }

    #[test]
    fn renders_language_from_langid() {
        let mut renderer = ResourceRenderer::new("assets");

        renderer.write_language(0x0409);

        assert_eq!(renderer.rc_text, "LANGUAGE 9, 1\n");
    }

    #[test]
    fn renders_safe_named_resource_keys_without_quotes() {
        assert_eq!(
            rc_resource_key(&ResourceKey::Name("CURS.ARROW".to_owned())),
            "CURS.ARROW"
        );
    }

    #[test]
    fn builds_icon_file_from_group_and_image_resources() {
        let group = ResourceLeaf {
            typ: ResourceKey::Id(pe::RT_GROUP_ICON),
            name: ResourceKey::Id(1),
            language: 0x0409,
            data: &[
                0, 0, 1, 0, 1, 0, // group header
                1, 1, 0, 0, 1, 0, 32, 0, 4, 0, 0, 0, 7, 0,
            ],
        };
        let images = BTreeMap::from([((0x0409, 7), &[0x11, 0x22, 0x33, 0x44][..])]);

        let (file, consumed) = build_icon_file(&group, IconFileKind::Icon, &images).unwrap();

        assert_eq!(consumed, vec![(0x0409, 7)]);
        assert_eq!(&file[..6], &[0, 0, 1, 0, 1, 0]);
        assert_eq!(&file[18..22], &[22, 0, 0, 0]);
        assert_eq!(&file[22..], &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn builds_cursor_file_from_group_and_resource_payload() {
        let group = ResourceLeaf {
            typ: ResourceKey::Id(pe::RT_GROUP_CURSOR),
            name: ResourceKey::Id(2),
            language: 0x0409,
            data: &[
                0, 0, 2, 0, 1, 0, // group header
                16, 0, 34, 0, 1, 0, 1, 0, 8, 0, 0, 0, 5, 0,
            ],
        };
        let images = BTreeMap::from([((0x0409, 5), &[3, 0, 4, 0, 0xAA, 0xBB, 0xCC, 0xDD][..])]);

        let (file, consumed) = build_icon_file(&group, IconFileKind::Cursor, &images).unwrap();

        assert_eq!(consumed, vec![(0x0409, 5)]);
        assert_eq!(&file[..6], &[0, 0, 2, 0, 1, 0]);
        assert_eq!(&file[6..14], &[16, 17, 0, 0, 3, 0, 4, 0]);
        assert_eq!(&file[14..22], &[4, 0, 0, 0, 22, 0, 0, 0]);
        assert_eq!(&file[22..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
