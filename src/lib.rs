use std::fmt;

mod functions;
mod resources;

pub use functions::{
    DisassembledInstruction, DiscoveredFunction, ExtractedObject, default_output_path,
    discover_function_addresses, discover_functions, extract_function_object,
    extract_function_objects, parse_address,
};
pub use resources::{ExtractedResources, ResourceAsset, extract_resource_script};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
