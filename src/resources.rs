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
        ResourceKey::Name(name) => format!("\"{}\"", escape_rc_text(name)),
    }
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
            0x22 => output.push_str("\\\""),
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

        assert_eq!(escape_rc_utf16_string(&units), "A\\\"\\\\\\n\\x263A");
    }

    #[test]
    fn renders_language_from_langid() {
        let mut renderer = ResourceRenderer::new("assets");

        renderer.write_language(0x0409);

        assert_eq!(renderer.rc_text, "LANGUAGE 9, 1\n");
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
