use std::collections::BTreeMap;

use serde_json::Value;

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

pub fn extract_function_mapping(source: &str, ast_json: &str) -> Result<FunctionMapping> {
    let binary = parse_binary_name(source);
    let map = parse_function_mapping_ast(ast_json)?;
    Ok(FunctionMapping { binary, map })
}

pub fn parse_function_mapping_ast(ast_json: &str) -> Result<Vec<MappingEntry>> {
    let ast: Value = serde_json::from_str(ast_json)
        .map_err(|err| Error::new(format!("failed to parse clang AST JSON: {err}")))?;
    let mut entries = BTreeMap::new();
    collect_function_entries(&ast, &mut entries)?;
    let mut entries = entries
        .into_iter()
        .map(|(name, address)| MappingEntry { name, address })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(entries)
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
                if let Some(previous) = entries.insert(name.to_owned(), address) {
                    if previous != address {
                        return Err(Error::new(format!(
                            "function `{name}` is mapped to both 0x{previous:08X} and 0x{address:08X}"
                        )));
                    }
                }
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
