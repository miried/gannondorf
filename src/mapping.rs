use std::collections::BTreeMap;

use serde_json::Value;
use tree_sitter::{Node, Parser};

use crate::{Error, Result, parse_address};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionMapping {
    pub binary: Option<String>,
    pub map: Vec<MappingEntry>,
    pub data: Vec<DataMappingEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMappingEntry {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FuncAnnotation {
    address: u64,
    end_byte: usize,
    line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CppFunction {
    name: Option<String>,
    start_byte: usize,
}

pub fn extract_function_mapping(source: &str) -> Result<FunctionMapping> {
    let binary = parse_binary_name(source);
    let map = parse_function_mapping_source(source)?;
    let data = parse_data_mapping_source(source)?;
    Ok(FunctionMapping { binary, map, data })
}

pub fn parse_function_mapping_ast(ast_json: &str) -> Result<Vec<MappingEntry>> {
    let ast: Value = serde_json::from_str(ast_json)
        .map_err(|err| Error::new(format!("failed to parse clang AST JSON: {err}")))?;
    let mut entries = BTreeMap::new();
    collect_function_entries(&ast, &mut entries)?;
    Ok(sorted_mapping_entries(entries))
}

pub fn parse_mapping_file(text: &str) -> Result<FunctionMapping> {
    let mut binary = None;
    let mut entries = Vec::new();
    let mut data = Vec::new();
    let mut in_map = false;
    let mut in_data = false;

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if in_map || in_data {
            if line == "}" {
                in_map = false;
                in_data = false;
                continue;
            }
            if in_data {
                let entry: Value =
                    serde_json::from_str(&format!("{{{}}}", line.trim_end_matches(','))).map_err(
                        |err| {
                            Error::new(format!("invalid data entry on line {line_number}: {err}"))
                        },
                    )?;
                let (name, fields) =
                    entry.as_object().unwrap().iter().next().ok_or_else(|| {
                        Error::new(format!("empty data entry on line {line_number}"))
                    })?;
                if entry.as_object().unwrap().len() != 1
                    || fields.as_object().is_none_or(|o| o.len() != 2)
                {
                    return Err(Error::new(format!(
                        "expected one data name with address and size on line {line_number}"
                    )));
                }
                let number = |key: &str| -> Result<u64> {
                    fields.get(key).and_then(Value::as_u64).ok_or_else(|| {
                        Error::new(format!(
                            "data {key} must be an unsigned integer on line {line_number}"
                        ))
                    })
                };
                data.push(DataMappingEntry {
                    name: name.clone(),
                    address: number("address")?,
                    size: number("size")?,
                });
            } else {
                entries.push(parse_mapping_entry_line(line, line_number)?);
            }
            continue;
        }

        if let Some(value) = line.strip_prefix("binary") {
            binary = Some(parse_binary_line(value, line_number)?);
        } else if line == "map = {" {
            in_map = true;
        } else if line == "data = {" {
            in_data = true;
        } else {
            return Err(Error::new(format!(
                "unexpected mapping line {line_number}: `{line}`"
            )));
        }
    }

    if in_map || in_data {
        return Err(Error::new("mapping file ended before closing `}`"));
    }

    validate_data_entries(&mut data)?;
    Ok(FunctionMapping {
        binary: binary.flatten(),
        map: entries,
        data,
    })
}

fn validate_data_entries(entries: &mut Vec<DataMappingEntry>) -> Result<()> {
    let mut names = BTreeMap::new();
    for entry in entries.iter() {
        if entry.name.is_empty()
            || entry.size == 0
            || entry.address.checked_add(entry.size).is_none()
        {
            return Err(Error::new(format!(
                "invalid data range for `{}`: size must be positive and address + size must not overflow",
                entry.name
            )));
        }
        if let Some(previous) = names.insert(&entry.name, (entry.address, entry.size))
            && previous != (entry.address, entry.size)
        {
            return Err(Error::new(format!(
                "conflicting data entries for `{}`",
                entry.name
            )));
        }
    }
    entries.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
    entries.dedup();
    Ok(())
}

fn parse_data_mapping_source(source: &str) -> Result<Vec<DataMappingEntry>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|err| Error::new(format!("failed to load C++ parser: {err}")))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| Error::new("failed to parse C++ source"))?;
    let mut entries = Vec::new();
    let mut end_byte = 0;
    for (index, line) in source.split_inclusive('\n').enumerate() {
        end_byte += line.len();
        let Some(text) = doc_comment_text(line).and_then(|s| s.strip_prefix("DATA ")) else {
            continue;
        };
        let fields: Vec<_> = text.split_whitespace().collect();
        if fields.len() != 2 {
            return Err(Error::new(format!(
                "DATA annotation on line {} requires an address and explicit byte size",
                index + 1
            )));
        }
        let declaration = next_data_declaration(tree.root_node(), end_byte).ok_or_else(|| {
            Error::new(format!(
                "DATA annotation on line {} is not followed by a variable declaration",
                index + 1
            ))
        })?;
        let mut parent = declaration.parent();
        while let Some(scope) = parent {
            if matches!(
                scope.kind(),
                "compound_statement" | "field_declaration_list"
            ) {
                return Err(Error::new(format!(
                    "DATA annotation on line {} requires a global variable",
                    index + 1
                )));
            }
            parent = scope.parent();
        }
        let mut cursor = declaration.walk();
        let declarators: Vec<_> = declaration
            .children_by_field_name("declarator", &mut cursor)
            .collect();
        if declaration.kind() != "declaration" || declaration.has_error() || declarators.len() != 1
        {
            return Err(Error::new(format!(
                "DATA annotation on line {} requires exactly one variable declarator",
                index + 1
            )));
        }
        let declarator = declarators[0];
        if contains_kind(declarator, "function_declarator") {
            return Err(Error::new(format!(
                "DATA annotation on line {} cannot annotate a function or function pointer",
                index + 1
            )));
        }
        let name = name_from_declarator(declarator, source)?.ok_or_else(|| {
            Error::new(format!(
                "DATA annotation on line {} has no variable name",
                index + 1
            ))
        })?;
        entries.push(DataMappingEntry {
            name,
            address: parse_address(fields[0])?,
            size: parse_address(fields[1])?,
        });
    }
    validate_data_entries(&mut entries)?;
    Ok(entries)
}

// Stop at the next declaration, including unsupported declarations, so an
// annotation cannot silently drift past a function or typedef to another global.
fn next_data_declaration(node: Node<'_>, after: usize) -> Option<Node<'_>> {
    if node.end_byte() <= after {
        return None;
    }
    if node.start_byte() >= after
        && matches!(
            node.kind(),
            "declaration" | "function_definition" | "type_definition" | "field_declaration"
        )
    {
        return Some(node);
    }
    for index in 0..node.named_child_count() {
        if let Some(found) = node
            .named_child(index as u32)
            .and_then(|child| next_data_declaration(child, after))
        {
            return Some(found);
        }
    }
    None
}

fn parse_binary_line(value: &str, line_number: usize) -> Result<Option<String>> {
    let value = value
        .trim_start()
        .strip_prefix('=')
        .ok_or_else(|| Error::new(format!("invalid binary entry on line {line_number}")))?
        .trim();
    if value == "null" {
        return Ok(None);
    }
    parse_quoted_string(value, line_number).map(Some)
}

fn parse_mapping_entry_line(line: &str, line_number: usize) -> Result<MappingEntry> {
    let line = line.strip_suffix(',').unwrap_or(line).trim_end();
    let (name, address) = line
        .split_once(':')
        .ok_or_else(|| Error::new(format!("invalid map entry on line {line_number}")))?;
    Ok(MappingEntry {
        name: parse_quoted_string(name.trim(), line_number)?,
        address: parse_address(address.trim())?,
    })
}

fn parse_quoted_string(value: &str, line_number: usize) -> Result<String> {
    serde_json::from_str(value)
        .map_err(|err| Error::new(format!("invalid string on line {line_number}: {err}")))
}

fn parse_function_mapping_source(source: &str) -> Result<Vec<MappingEntry>> {
    let annotations = parse_func_annotations(source)?;
    let functions = parse_cpp_functions(source)?;
    let mut entries = BTreeMap::new();

    for annotation in annotations {
        let function = functions
            .iter()
            .find(|function| function.start_byte >= annotation.end_byte)
            .ok_or_else(|| {
                Error::new(format!(
                    "FUNC annotation on line {} is not followed by a function declaration or definition",
                    annotation.line
                ))
            })?;

        let name = function.name.as_deref().ok_or_else(|| {
            Error::new(format!(
                "function declaration after FUNC annotation on line {} has no extractable name",
                annotation.line
            ))
        })?;

        insert_mapping_entry(&mut entries, name, annotation.address)?;
    }

    Ok(sorted_mapping_entries(entries))
}

fn parse_func_annotations(source: &str) -> Result<Vec<FuncAnnotation>> {
    let mut annotations = Vec::new();
    let mut line_start = 0;

    for (line_index, line) in source.split_inclusive('\n').enumerate() {
        let line_end = line_start + line.len();
        let line_text = line.trim_end_matches('\n').trim_end_matches('\r');
        if let Some(text) = doc_comment_text(line_text) {
            if let Some(address) = text.trim().strip_prefix("FUNC ") {
                annotations.push(FuncAnnotation {
                    address: parse_address(address.trim())?,
                    end_byte: line_end,
                    line: line_index + 1,
                });
            }
        }
        line_start = line_end;
    }

    Ok(annotations)
}

fn parse_cpp_functions(source: &str) -> Result<Vec<CppFunction>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .map_err(|err| Error::new(format!("failed to load C++ parser: {err}")))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| Error::new("failed to parse C++ source"))?;

    let mut functions = Vec::new();
    collect_cpp_functions(tree.root_node(), source, &mut functions)?;
    functions.sort_by_key(|function| function.start_byte);
    functions.dedup_by_key(|function| function.start_byte);
    Ok(functions)
}

fn collect_cpp_functions(
    node: Node<'_>,
    source: &str,
    functions: &mut Vec<CppFunction>,
) -> Result<()> {
    if node.kind() == "function_declarator" {
        if is_function_declaration_declarator(node) && !is_function_pointer_type_declarator(node) {
            functions.push(CppFunction {
                name: function_name_from_declarator(node, source)?,
                start_byte: node.start_byte(),
            });
        }
        return Ok(());
    }

    for index in 0..node.named_child_count() {
        if let Some(child) = node.named_child(index as u32) {
            collect_cpp_functions(child, source, functions)?;
        }
    }

    Ok(())
}

fn is_function_declaration_declarator(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "declaration" | "field_declaration" | "function_definition" => return true,
            "alias_declaration"
            | "optional_parameter_declaration"
            | "parameter_declaration"
            | "preproc_function_def"
            | "type_definition"
            | "variadic_parameter_declaration" => {
                return false;
            }
            _ => current = parent,
        }
    }
    false
}

fn is_function_pointer_type_declarator(node: Node<'_>) -> bool {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return false;
    };

    declarator.kind() == "parenthesized_declarator"
        && (contains_kind(declarator, "pointer_declarator")
            || contains_kind(declarator, "reference_declarator"))
        && !contains_nested_function_declarator(declarator)
}

fn contains_kind(node: Node<'_>, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }

    for index in 0..node.named_child_count() {
        if let Some(child) = node.named_child(index as u32) {
            if contains_kind(child, kind) {
                return true;
            }
        }
    }

    false
}

fn contains_nested_function_declarator(node: Node<'_>) -> bool {
    for index in 0..node.named_child_count() {
        let Some(child) = node.named_child(index as u32) else {
            continue;
        };
        if child.kind() == "function_declarator" || contains_nested_function_declarator(child) {
            return true;
        }
    }

    false
}

fn function_name_from_declarator(node: Node<'_>, source: &str) -> Result<Option<String>> {
    let declarator = node.child_by_field_name("declarator").unwrap_or(node);
    name_from_declarator(declarator, source)
}

fn name_from_declarator(node: Node<'_>, source: &str) -> Result<Option<String>> {
    match node.kind() {
        "destructor_name" | "field_identifier" | "identifier" | "operator_cast"
        | "operator_name" | "type_identifier" => return node_text(node, source).map(Some),
        _ => {}
    }

    if let Some(declarator) = node.child_by_field_name("declarator") {
        if let Some(name) = name_from_declarator(declarator, source)? {
            return Ok(Some(name));
        }
    }

    let mut name = None;
    for index in 0..node.named_child_count() {
        let Some(child) = node.named_child(index as u32) else {
            continue;
        };
        if matches!(
            child.kind(),
            "argument_list" | "compound_statement" | "parameter_list"
        ) {
            continue;
        }
        if let Some(child_name) = name_from_declarator(child, source)? {
            name = Some(child_name);
        }
    }

    Ok(name)
}

fn node_text(node: Node<'_>, source: &str) -> Result<String> {
    node.utf8_text(source.as_bytes())
        .map(str::trim)
        .map(str::to_owned)
        .map_err(|err| Error::new(format!("failed to read C++ syntax node text: {err}")))
}

fn parse_binary_name(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let text = doc_comment_text(line)?;
        text.strip_prefix("FILE ")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn doc_comment_text(line: &str) -> Option<&str> {
    line.trim_start()
        .strip_prefix("//!")
        .or_else(|| line.trim_start().strip_prefix("///"))
        .map(str::trim_start)
}

fn collect_function_entries(node: &Value, entries: &mut BTreeMap<String, u64>) -> Result<()> {
    if let Some(object) = node.as_object() {
        if object.get("kind").and_then(Value::as_str) == Some("FunctionDecl") {
            if let Some(address) = function_address_from_decl(node)? {
                let name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::new("mapped FunctionDecl is missing a name"))?;
                insert_mapping_entry(entries, name, address)?;
            }
        }

        if let Some(inner) = object.get("inner").and_then(Value::as_array) {
            for child in inner {
                collect_function_entries(child, entries)?;
            }
        }
    }

    Ok(())
}

fn insert_mapping_entry(
    entries: &mut BTreeMap<String, u64>,
    name: &str,
    address: u64,
) -> Result<()> {
    if let Some(previous) = entries.insert(name.to_owned(), address) {
        if previous != address {
            return Err(Error::new(format!(
                "function `{name}` is mapped to both 0x{previous:08X} and 0x{address:08X}"
            )));
        }
    }
    Ok(())
}

fn sorted_mapping_entries(entries: BTreeMap<String, u64>) -> Vec<MappingEntry> {
    let mut entries = entries
        .into_iter()
        .map(|(name, address)| MappingEntry { name, address })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.name.cmp(&right.name))
    });
    entries
}

fn function_address_from_decl(decl: &Value) -> Result<Option<u64>> {
    let mut comment_text = Vec::new();
    if let Some(inner) = decl.get("inner").and_then(Value::as_array) {
        for child in inner {
            if child.get("kind").and_then(Value::as_str) == Some("FullComment") {
                collect_text_comments(child, &mut comment_text);
            }
        }
    }

    for text in comment_text {
        if let Some(address) = text.trim().strip_prefix("FUNC ") {
            return parse_address(address.trim()).map(Some);
        }
    }

    Ok(None)
}

fn collect_text_comments(node: &Value, comments: &mut Vec<String>) {
    if let Some(object) = node.as_object() {
        if object.get("kind").and_then(Value::as_str) == Some("TextComment") {
            if let Some(text) = object.get("text").and_then(Value::as_str) {
                comments.push(text.to_owned());
            }
        }

        if let Some(inner) = object.get("inner").and_then(Value::as_array) {
            for child in inner {
                collect_text_comments(child, comments);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_annotations_have_explicit_sizes_and_are_separate() {
        let mapping = extract_function_mapping(
            r#"
//! FILE globals.exe
extern "C" {
//! DATA 0x402000 4
volatile int initialized = 0x12345678;
//! DATA 0x402018 4
volatile int uninitialized;
//! DATA 0x402008 0x10
volatile int values[4] = {11, 22, 33, 44};
}
//! FUNC 0x401000
int entry() { return values[2]; }
"#,
        )
        .unwrap();
        assert_eq!(mapping.map.len(), 1);
        assert_eq!(
            mapping.data,
            vec![
                DataMappingEntry {
                    name: "initialized".into(),
                    address: 0x402000,
                    size: 4
                },
                DataMappingEntry {
                    name: "values".into(),
                    address: 0x402008,
                    size: 16
                },
                DataMappingEntry {
                    name: "uninitialized".into(),
                    address: 0x402018,
                    size: 4
                },
            ]
        );
    }

    #[test]
    fn rejects_ambiguous_or_invalid_data_annotations() {
        for source in [
            "//! DATA 0x402000\nint x;",
            "//! DATA 0x402000 0\nint x;",
            "//! DATA 0xffffffffffffffff 4\nint x;",
            "//! DATA 0x402000 4\nint x, y;",
            "//! DATA 0x402000 4\nint f();\nint x;",
            "void f() {\n//! DATA 0x402000 4\nint x;\n}",
            "//! DATA 0x402000 4\ntypedef int X;\nint x;",
            "//! DATA 0x402000 4\n",
            "//! DATA 0x402000 4\nint x;\n//! DATA 0x402004 4\nint x;",
        ] {
            assert!(
                extract_function_mapping(source).is_err(),
                "accepted {source}"
            );
        }
    }

    #[test]
    fn reads_data_only_and_legacy_maps_and_rejects_invalid_sizes() {
        let mapping = parse_mapping_file(
            "binary = null\ndata = {\n\"x\": {\"address\": 4202496, \"size\": 4},\n}\n",
        )
        .unwrap();
        assert!(mapping.map.is_empty());
        assert_eq!(mapping.data[0].size, 4);
        assert!(
            parse_mapping_file("map = {\n\"f\": 0x401000,\n}\n")
                .unwrap()
                .data
                .is_empty()
        );
        for fields in [
            "\"address\": 1",
            "\"address\": 1, \"size\": 0",
            "\"address\": 1, \"size\": -4",
            "\"address\": 1, \"size\": 1.5",
            "\"address\": 18446744073709551615, \"size\": 4",
        ] {
            assert!(parse_mapping_file(&format!("data = {{\n\"x\": {{{fields}}},\n}}\n")).is_err());
        }
        assert!(parse_mapping_file("data = {\n").is_err());
    }

    #[test]
    fn extracts_binary_from_source_doc_comment() {
        let source = "//! FILE TI.EXE\n\n//! FUNC 0x0041bb40\nvoid f() {}\n";
        assert_eq!(parse_binary_name(source).as_deref(), Some("TI.EXE"));
    }

    #[test]
    fn extracts_function_mapping_from_cpp_source() {
        let source = include_str!("../tests/mapping_test.cpp");

        assert_eq!(
            extract_function_mapping(source).unwrap(),
            FunctionMapping {
                binary: Some("TI.EXE".to_owned()),
                data: vec![],
                map: vec![
                    MappingEntry {
                        name: "fn_0041bb40".to_owned(),
                        address: 0x0041bb40,
                    },
                    MappingEntry {
                        name: "WinMain".to_owned(),
                        address: 0x004321D0,
                    },
                ],
            }
        );
    }

    #[test]
    fn parses_common_cpp_declaration_shapes() {
        let source = r#"
//! FUNC 0x00410000
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);

//! FUNC 0x00410010
char *fn_returns_pointer();

//! FUNC 0x00410020
void App::run() {}
"#;

        assert_eq!(
            extract_function_mapping(source).unwrap().map,
            vec![
                MappingEntry {
                    name: "WinMain".to_owned(),
                    address: 0x00410000,
                },
                MappingEntry {
                    name: "fn_returns_pointer".to_owned(),
                    address: 0x00410010,
                },
                MappingEntry {
                    name: "run".to_owned(),
                    address: 0x00410020,
                },
            ]
        );
    }

    #[test]
    fn ignores_function_type_declarators_between_annotation_and_function() {
        let source = r#"
typedef void (*Callback)(int);

//! FUNC 0x00410000
void (*callback_value)(int);
typedef int (*IgnoredFactory)();
void real_function();
"#;

        assert_eq!(
            extract_function_mapping(source).unwrap().map,
            vec![MappingEntry {
                name: "real_function".to_owned(),
                address: 0x00410000,
            }]
        );
    }

    #[test]
    fn parses_function_returning_function_pointer() {
        let source = r#"
//! FUNC 0x00410000
int (*make_callback())(int);
"#;

        assert_eq!(
            extract_function_mapping(source).unwrap().map,
            vec![MappingEntry {
                name: "make_callback".to_owned(),
                address: 0x00410000,
            }]
        );
    }

    #[test]
    fn rejects_conflicting_addresses_for_same_function_name() {
        let source = r#"
//! FUNC 0x00410000
void f();

//! FUNC 0x00410010
void f();
"#;

        let error = extract_function_mapping(source).unwrap_err();
        assert_eq!(
            error.to_string(),
            "function `f` is mapped to both 0x00410000 and 0x00410010"
        );
    }

    #[test]
    fn rejects_func_annotation_without_following_function() {
        let source = "//! FUNC 0x00410000\nint global_value;\n";

        let error = extract_function_mapping(source).unwrap_err();
        assert_eq!(
            error.to_string(),
            "FUNC annotation on line 1 is not followed by a function declaration or definition"
        );
    }

    #[test]
    fn extracts_function_mapping_from_clang_ast_comments() {
        let ast = r#"
        {
          "kind": "TranslationUnitDecl",
          "inner": [
            {
              "kind": "FunctionDecl",
              "name": "fn_0041bb40",
              "inner": [
                {
                  "kind": "FullComment",
                  "inner": [
                    {
                      "kind": "ParagraphComment",
                      "inner": [
                        {
                          "kind": "TextComment",
                          "text": " FUNC 0x0041bb40"
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            {
              "kind": "FunctionDecl",
              "name": "WinMain",
              "inner": [
                {
                  "kind": "FullComment",
                  "inner": [
                    {
                      "kind": "TextComment",
                      "text": " FUNC 0x004321D0"
                    }
                  ]
                }
              ]
            }
          ]
        }
        "#;

        assert_eq!(
            parse_function_mapping_ast(ast).unwrap(),
            vec![
                MappingEntry {
                    name: "fn_0041bb40".to_owned(),
                    address: 0x0041bb40,
                },
                MappingEntry {
                    name: "WinMain".to_owned(),
                    address: 0x004321D0,
                },
            ]
        );
    }
}
