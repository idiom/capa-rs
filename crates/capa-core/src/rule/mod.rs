//! CAPA rule parsing and representation
//!
//! This module handles parsing YAML rules into an AST for matching.

mod parser;
mod types;
mod validation;

pub use parser::{parse_rule, parse_rule_file, parse_rules_directory};
pub use types::*;
pub use validation::validate_rule;
