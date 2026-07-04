use std::collections::BTreeMap;

use serde_json::Value;
use tree_sitter::{Node, Parser};

use crate::{Error, Result, parse_address};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionMapping {
    pub binary: Option<String>,
    pub map: Vec<MappingEntry>,
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
    Ok(FunctionMapping { binary, map })
}

pub fn parse_function_mapping_ast(ast_json: &str) -> Result<Vec<MappingEntry>> {
    let ast: Value = serde_json::from_str(ast_json)
        .map_err(|err| Error::new(format!("failed to parse clang AST JSON: {err}")))?;
    let mut entries = BTreeMap::new();
    collect_function_entries(&ast, &mut entries)?;
    Ok(sorted_mapping_entries(entries))
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
