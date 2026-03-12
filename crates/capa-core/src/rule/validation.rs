//! Rule validation
//!
//! Validates parsed rules for correctness and consistency.

use crate::error::{CapaError, Result};
use crate::rule::types::*;

/// Validate a parsed rule
pub fn validate_rule(rule: &Rule) -> Result<()> {
    // Validate required fields
    if rule.meta.name.is_empty() {
        return Err(CapaError::ValidationError(
            "Rule name cannot be empty".to_string(),
        ));
    }

    // Validate features tree is not empty
    validate_feature_node(&rule.features)?;

    Ok(())
}

fn validate_feature_node(node: &FeatureNode) -> Result<()> {
    match node {
        FeatureNode::And(children) | FeatureNode::Or(children) | FeatureNode::Optional(children) | FeatureNode::Instruction(children) | FeatureNode::BasicBlock(children) | FeatureNode::Function(children) => {
            if children.is_empty() {
                return Err(CapaError::ValidationError(
                    "Boolean operator cannot have empty children".to_string(),
                ));
            }
            for child in children {
                validate_feature_node(child)?;
            }
        }
        FeatureNode::Not(child) => {
            validate_feature_node(child)?;
        }
        FeatureNode::NOrMore(n, children) => {
            if children.len() < *n {
                return Err(CapaError::ValidationError(format!(
                    "NOrMore({}) has fewer than {} children",
                    n,
                    n
                )));
            }
            for child in children {
                validate_feature_node(child)?;
            }
        }
        FeatureNode::Count(child, constraint) => {
            validate_feature_node(child)?;
            validate_count_constraint(constraint)?;
        }
        FeatureNode::Description(_, child) => {
            validate_feature_node(child)?;
        }
        FeatureNode::Feature(_) | FeatureNode::Match(_) => {
            // Leaf nodes are valid
        }
    }
    Ok(())
}

fn validate_count_constraint(constraint: &CountConstraint) -> Result<()> {
    match constraint {
        CountConstraint::Range(min, max) => {
            if min > max {
                return Err(CapaError::ValidationError(format!(
                    "Invalid count range: {} > {}",
                    min, max
                )));
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_name() {
        let rule = Rule {
            meta: RuleMeta {
                name: String::new(),
                namespace: None,
                authors: vec![],
                description: None,
                scopes: Scopes::default(),
                scope: None,
                attack: vec![],
                mbc: vec![],
                references: vec![],
                examples: vec![],
                is_lib: false,
                maec: None,
            },
            features: FeatureNode::And(vec![]),
            source_path: None,
        };
        assert!(validate_rule(&rule).is_err());
    }
}
