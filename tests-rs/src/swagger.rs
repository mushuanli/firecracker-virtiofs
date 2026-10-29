// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Firecracker API schema validation, ported from
//! `tests/framework/swagger_validator.py`.
//!
//! The python version builds `jsonschema` Draft4 validators from
//! `src/firecracker/swagger/firecracker.yaml`. This port keeps the same
//! request/response keying and path normalisation, and implements the JSON
//! Schema subset the Firecracker spec actually uses: `$ref`, `type`,
//! `required`, `properties`, `additionalProperties`, `items`, `enum`,
//! `minimum`, `maximum` and `pattern`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::defs;

/// A schema validation failure.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct SwaggerError {
    pub message: String,
}

impl SwaggerError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Which side of the exchange a validator applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Direction {
    Request,
    Response,
}

/// Cached validator table, keyed like the python `_validators` dict.
#[derive(Debug)]
pub struct SwaggerValidator {
    spec: Value,
    validators: BTreeMap<(Direction, String, String, Option<String>), Value>,
}

impl SwaggerValidator {
    /// Loads the spec at `path` and builds the validator table.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading swagger spec {}", path.display()))?;
        let yaml: serde_yaml::Value = serde_yaml::from_str(&text)
            .with_context(|| format!("parsing swagger spec {}", path.display()))?;
        let spec: Value = serde_json::to_value(yaml).context("converting swagger spec to JSON")?;
        Ok(Self::from_spec(spec))
    }

    /// Builds the validator table from an already-parsed spec.
    pub fn from_spec(spec: Value) -> Self {
        let mut validator = Self {
            spec,
            validators: BTreeMap::new(),
        };
        validator.build_validators();
        validator
    }

    /// The shared validator, loaded once from the workspace spec.
    ///
    /// Returns `None` when the spec is missing, which makes API validation a
    /// no-op instead of failing every microVM spawn.
    pub fn shared() -> Option<&'static SwaggerValidator> {
        static SHARED: OnceLock<Option<SwaggerValidator>> = OnceLock::new();
        SHARED
            .get_or_init(|| Self::load(&spec_path()).ok())
            .as_ref()
    }

    fn build_validators(&mut self) {
        let definitions = self
            .spec
            .get("definitions")
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()));
        let Some(paths) = self.spec.get("paths").and_then(|p| p.as_object()) else {
            return;
        };

        for (path, methods) in paths {
            let Some(methods) = methods.as_object() else {
                continue;
            };
            for (method, spec) in methods {
                let method = method.to_uppercase();
                if !matches!(method.as_str(), "GET" | "PUT" | "PATCH" | "POST" | "DELETE") {
                    continue;
                }

                // Request body validators.
                if let Some(parameters) = spec.get("parameters").and_then(|p| p.as_array()) {
                    for param in parameters {
                        if param.get("in").and_then(|v| v.as_str()) != Some("body") {
                            continue;
                        }
                        let Some(schema) = param.get("schema") else {
                            continue;
                        };
                        let mut resolved = self.resolve_schema(schema, &definitions);
                        if method == "PATCH" {
                            // Do not validate required fields on PATCH requests.
                            resolved["required"] = Value::Array(Vec::new());
                        }
                        self.validators.insert(
                            (Direction::Request, method.clone(), path.clone(), None),
                            resolved,
                        );
                    }
                }

                // Response validators for 200/204.
                if let Some(responses) = spec.get("responses").and_then(|r| r.as_object()) {
                    for (status, response_spec) in responses {
                        if status != "200" && status != "204" {
                            continue;
                        }
                        let Some(schema) = response_spec.get("schema") else {
                            continue;
                        };
                        let resolved = self.resolve_schema(schema, &definitions);
                        self.validators.insert(
                            (
                                Direction::Response,
                                method.clone(),
                                path.clone(),
                                Some(status.clone()),
                            ),
                            resolved,
                        );
                    }
                }
            }
        }
    }

    fn resolve_schema(&self, schema: &Value, definitions: &Value) -> Value {
        let Some(obj) = schema.as_object() else {
            return schema.clone();
        };
        let mut resolved = obj.clone();

        if let Some(reference) = obj.get("$ref").and_then(|r| r.as_str()) {
            if let Some(name) = reference.rsplit('/').next() {
                if let Some(target) = definitions.get(name) {
                    let mut inner = self.resolve_schema(target, definitions);
                    // Merge siblings of the `$ref` (none in practice, but keep
                    // the python merge semantics).
                    if let (Some(inner_obj), Some(extra)) = (inner.as_object_mut(), Some(obj)) {
                        for (key, value) in extra {
                            if key != "$ref" {
                                inner_obj.insert(key.clone(), value.clone());
                            }
                        }
                    }
                    return inner;
                }
            }
        }

        if let Some(properties) = obj.get("properties").and_then(|p| p.as_object()) {
            let mut resolved_props = serde_json::Map::new();
            for (name, property) in properties {
                resolved_props.insert(name.clone(), self.resolve_schema(property, definitions));
            }
            resolved.insert("properties".into(), Value::Object(resolved_props));
        }

        if let Some(items) = obj.get("items") {
            let resolved_items = self.resolve_schema(items, definitions);
            resolved.insert("items".into(), resolved_items);
        }

        if !resolved.contains_key("additionalProperties") {
            resolved.insert("additionalProperties".into(), Value::Bool(false));
        }

        Value::Object(resolved)
    }

    /// Validates a request body against the spec.
    pub fn validate_request(&self, method: &str, path: &str, body: &Value) -> Result<()> {
        self.validate(Direction::Request, method, path, None, body)
    }

    /// Validates a response body against the spec.
    pub fn validate_response(
        &self,
        method: &str,
        path: &str,
        status_code: u16,
        body: &Value,
    ) -> Result<()> {
        self.validate(
            Direction::Response,
            method,
            path,
            Some(status_code.to_string()),
            body,
        )
    }

    fn validate(
        &self,
        direction: Direction,
        method: &str,
        path: &str,
        status: Option<String>,
        body: &Value,
    ) -> Result<()> {
        let normalized = self.normalize_path(path);
        let key = (
            direction,
            method.to_uppercase(),
            normalized.clone(),
            status.clone(),
        );
        let Some(schema) = self.validators.get(&key) else {
            bail!(
                "({:?}, {}, {}, {:?}) is not in the schema",
                direction,
                method.to_uppercase(),
                normalized,
                status
            );
        };
        let cleaned = filter_none_recursive(body);
        validate_value(&cleaned, schema, &self.spec, "$")
            .map_err(|err| anyhow::anyhow!("{} {}: {}", method.to_uppercase(), normalized, err))?;
        Ok(())
    }

    /// Replaces concrete ids with the spec's parameter placeholders.
    pub fn normalize_path(&self, path: &str) -> String {
        let Some(paths) = self.spec.get("paths").and_then(|p| p.as_object()) else {
            return path.to_string();
        };
        if paths.contains_key(path) {
            return path.to_string();
        }

        let parts: Vec<&str> = path.split('/').collect();
        for swagger_path in paths.keys() {
            let swagger_parts: Vec<&str> = swagger_path.split('/').collect();
            if parts.len() != swagger_parts.len() {
                continue;
            }
            let matches = parts.iter().zip(&swagger_parts).all(|(part, spec_part)| {
                (spec_part.starts_with('{') && spec_part.ends_with('}')) || part == spec_part
            });
            if matches {
                return swagger_path.clone();
            }
        }
        path.to_string()
    }
}

/// Path of the Firecracker Open API specification.
pub fn spec_path() -> PathBuf {
    defs::workspace_dir()
        .join("src")
        .join("firecracker")
        .join("swagger")
        .join("firecracker.yaml")
}

/// Recursively drops `null` values, matching `_filter_none_recursive`.
pub fn filter_none_recursive(data: &Value) -> Value {
    match data {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key.clone(), filter_none_recursive(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .filter(|value| !value.is_null())
                .map(filter_none_recursive)
                .collect(),
        ),
        other => other.clone(),
    }
}

fn validate_value(value: &Value, schema: &Value, root: &Value, location: &str) -> Result<()> {
    if let Some(reference) = schema.get("$ref").and_then(|r| r.as_str()) {
        let name = reference
            .rsplit('/')
            .next()
            .ok_or_else(|| SwaggerError::new(format!("{location}: malformed $ref {reference}")))?;
        let target = root
            .get("definitions")
            .and_then(|d| d.get(name))
            .ok_or_else(|| SwaggerError::new(format!("{location}: unresolved $ref {reference}")))?;
        return validate_value(value, target, root, location);
    }

    if let Some(expected) = schema.get("type").and_then(|t| t.as_str()) {
        let actual = json_type(value);
        let matches = expected == actual
            || (expected == "number" && actual == "integer")
            || (expected == "integer" && actual == "integer");
        if !matches {
            return Err(SwaggerError::new(format!(
                "{location}: expected {expected}, found {actual}"
            ))
            .into());
        }
    }

    if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
        if !enum_values.iter().any(|candidate| candidate == value) {
            return Err(SwaggerError::new(format!(
                "{location}: {value} is not one of {:?}",
                enum_values
            ))
            .into());
        }
    }

    if let Some(minimum) = schema.get("minimum").and_then(|m| m.as_f64()) {
        if let Some(actual) = value.as_f64() {
            if actual < minimum {
                return Err(SwaggerError::new(format!(
                    "{location}: {actual} is less than minimum {minimum}"
                ))
                .into());
            }
        }
    }

    if let Some(maximum) = schema.get("maximum").and_then(|m| m.as_f64()) {
        if let Some(actual) = value.as_f64() {
            if actual > maximum {
                return Err(SwaggerError::new(format!(
                    "{location}: {actual} is greater than maximum {maximum}"
                ))
                .into());
            }
        }
    }

    if let Some(pattern) = schema.get("pattern").and_then(|p| p.as_str()) {
        if let Some(text) = value.as_str() {
            let regex = regex::Regex::new(pattern)
                .map_err(|err| SwaggerError::new(format!("{location}: bad pattern: {err}")))?;
            if !regex.is_match(text) {
                return Err(SwaggerError::new(format!(
                    "{location}: {text:?} does not match {pattern:?}"
                ))
                .into());
            }
        }
    }

    match value {
        Value::Object(map) => validate_object(map, schema, root, location),
        Value::Array(items) => {
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    validate_value(item, item_schema, root, &format!("{location}[{index}]"))?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_object(
    map: &serde_json::Map<String, Value>,
    schema: &Value,
    root: &Value,
    location: &str,
) -> Result<()> {
    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        for field in required.iter().filter_map(|f| f.as_str()) {
            if !map.contains_key(field) {
                return Err(SwaggerError::new(format!(
                    "{location}: missing required field {field:?}"
                ))
                .into());
            }
        }
    }

    let properties = schema.get("properties").and_then(|p| p.as_object());
    for (key, value) in map {
        if let Some(property_schema) = properties.and_then(|p| p.get(key)) {
            validate_value(value, property_schema, root, &format!("{location}.{key}"))?;
            continue;
        }
        match schema.get("additionalProperties") {
            Some(Value::Bool(false)) => {
                return Err(SwaggerError::new(format!(
                    "{location}: additional property {key:?} is not allowed"
                ))
                .into());
            }
            Some(Value::Bool(true)) | None => {}
            Some(extra_schema) => {
                validate_value(value, extra_schema, root, &format!("{location}.{key}"))?;
            }
        }
    }
    Ok(())
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec() -> Value {
        json!({
            "paths": {
                "/drives/{drive_id}": {
                    "put": {
                        "parameters": [{
                            "in": "body",
                            "schema": { "$ref": "#/definitions/Drive" }
                        }],
                        "responses": { "204": { "description": "ok" } }
                    },
                    "patch": {
                        "parameters": [{
                            "in": "body",
                            "schema": { "$ref": "#/definitions/Drive" }
                        }],
                        "responses": { "204": { "description": "ok" } }
                    }
                },
                "/version": {
                    "get": {
                        "responses": {
                            "200": { "schema": { "$ref": "#/definitions/Version" } }
                        }
                    }
                }
            },
            "definitions": {
                "Drive": {
                    "type": "object",
                    "required": ["drive_id", "path_on_host"],
                    "properties": {
                        "drive_id": { "type": "string" },
                        "path_on_host": { "type": "string" },
                        "is_read_only": { "type": "boolean" }
                    }
                },
                "Version": {
                    "type": "object",
                    "required": ["firecracker_version"],
                    "properties": {
                        "firecracker_version": { "type": "string" }
                    },
                    "additionalProperties": true
                }
            }
        })
    }

    #[test]
    fn normalize_path_replaces_ids() {
        let validator = SwaggerValidator::from_spec(spec());
        assert_eq!(
            validator.normalize_path("/drives/rootfs"),
            "/drives/{drive_id}"
        );
        assert_eq!(validator.normalize_path("/version"), "/version");
        assert_eq!(
            validator.normalize_path("/unknown/thing/x"),
            "/unknown/thing/x"
        );
    }

    #[test]
    fn valid_request_passes() {
        let validator = SwaggerValidator::from_spec(spec());
        let body = json!({"drive_id": "rootfs", "path_on_host": "/tmp/rootfs.ext4"});
        validator
            .validate_request("PUT", "/drives/rootfs", &body)
            .unwrap();
    }

    #[test]
    fn missing_required_field_fails() {
        let validator = SwaggerValidator::from_spec(spec());
        let body = json!({"drive_id": "rootfs"});
        let err = validator
            .validate_request("PUT", "/drives/rootfs", &body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("path_on_host"), "{err}");
    }

    #[test]
    fn patch_does_not_require_fields() {
        let validator = SwaggerValidator::from_spec(spec());
        validator
            .validate_request("PATCH", "/drives/rootfs", &json!({"is_read_only": true}))
            .unwrap();
    }

    #[test]
    fn wrong_type_fails() {
        let validator = SwaggerValidator::from_spec(spec());
        let body = json!({"drive_id": 5, "path_on_host": "/tmp/x"});
        let err = validator
            .validate_request("PUT", "/drives/rootfs", &body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected string"), "{err}");
    }

    #[test]
    fn additional_properties_rejected_unless_allowed() {
        let validator = SwaggerValidator::from_spec(spec());
        let body = json!({
            "drive_id": "rootfs",
            "path_on_host": "/tmp/x",
            "bogus": 1
        });
        let err = validator
            .validate_request("PUT", "/drives/rootfs", &body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("additional property"), "{err}");

        validator
            .validate_response(
                "GET",
                "/version",
                200,
                &json!({"firecracker_version": "1.0", "extra": 1}),
            )
            .unwrap();
    }

    #[test]
    fn unknown_endpoint_is_an_error() {
        let validator = SwaggerValidator::from_spec(spec());
        assert!(validator
            .validate_request("PUT", "/nope", &json!({}))
            .unwrap_err()
            .to_string()
            .contains("not in the schema"));
    }

    #[test]
    fn null_values_are_filtered() {
        let validator = SwaggerValidator::from_spec(spec());
        let body = json!({"drive_id": "rootfs", "path_on_host": "/tmp/x", "is_read_only": null});
        validator
            .validate_request("PUT", "/drives/rootfs", &body)
            .unwrap();
        assert_eq!(
            filter_none_recursive(&body),
            json!({"drive_id": "rootfs", "path_on_host": "/tmp/x"})
        );
    }

    #[test]
    fn enum_and_range_checks() {
        let schema = json!({"type": "object", "properties": {
            "mode": {"enum": ["Sync", "Async"]},
            "count": {"type": "integer", "minimum": 1, "maximum": 32}
        }});
        let root = json!({});
        assert!(validate_value(&json!({"mode": "Sync", "count": 2}), &schema, &root, "$").is_ok());
        assert!(validate_value(&json!({"mode": "Nope", "count": 2}), &schema, &root, "$").is_err());
        assert!(validate_value(&json!({"count": 0}), &schema, &root, "$").is_err());
        assert!(validate_value(&json!({"count": 33}), &schema, &root, "$").is_err());
    }

    #[test]
    fn real_spec_loads_when_present() {
        let path = spec_path();
        if !path.exists() {
            return;
        }
        let validator = SwaggerValidator::load(&path).unwrap();
        assert_eq!(
            validator.normalize_path("/drives/rootfs"),
            "/drives/{drive_id}"
        );
        // The real `Drive` definition requires `drive_id` and `is_root_device`.
        assert!(validator
            .validate_request(
                "PUT",
                "/drives/rootfs",
                &json!({
                    "drive_id": "rootfs",
                    "is_root_device": true,
                    "path_on_host": "/tmp/rootfs.ext4"
                })
            )
            .is_ok());
        let err = validator
            .validate_request("PUT", "/drives/rootfs", &json!({"drive_id": "rootfs"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("is_root_device"), "{err}");
    }
}
