//! End-to-end integration tests for ocsf-proto-gen.
//!
//! These tests use a minimal embedded schema (not the full 3.3MB export)
//! to verify the complete pipeline: schema loading → codegen → proto validation.

use std::collections::BTreeMap;
use std::path::Path;

use ocsf_proto_gen::codegen;
use ocsf_proto_gen::schema::{OcsfAttribute, OcsfClass, OcsfEnumValue, OcsfObject, OcsfSchema};

/// Build a minimal but realistic schema for testing.
fn test_schema() -> OcsfSchema {
    let mut classes = BTreeMap::new();
    let mut objects = BTreeMap::new();

    // Authentication class with enum, object ref, and scalar fields.
    let mut auth_attrs = BTreeMap::new();
    auth_attrs.insert(
        "activity_id".to_string(),
        OcsfAttribute {
            type_name: "integer_t".to_string(),
            caption: "Activity ID".to_string(),
            enum_values: Some(BTreeMap::from([
                (
                    "0".to_string(),
                    OcsfEnumValue {
                        caption: "Unknown".to_string(),
                        description: None,
                    },
                ),
                (
                    "1".to_string(),
                    OcsfEnumValue {
                        caption: "Logon".to_string(),
                        description: None,
                    },
                ),
                (
                    "2".to_string(),
                    OcsfEnumValue {
                        caption: "Logoff".to_string(),
                        description: None,
                    },
                ),
                (
                    "99".to_string(),
                    OcsfEnumValue {
                        caption: "Other".to_string(),
                        description: None,
                    },
                ),
            ])),
            ..default_attr()
        },
    );
    auth_attrs.insert(
        "message".to_string(),
        OcsfAttribute {
            type_name: "string_t".to_string(),
            caption: "Message".to_string(),
            ..default_attr()
        },
    );
    auth_attrs.insert(
        "severity_id".to_string(),
        OcsfAttribute {
            type_name: "integer_t".to_string(),
            caption: "Severity ID".to_string(),
            enum_values: Some(BTreeMap::from([
                (
                    "0".to_string(),
                    OcsfEnumValue {
                        caption: "Unknown".to_string(),
                        description: None,
                    },
                ),
                (
                    "1".to_string(),
                    OcsfEnumValue {
                        caption: "Informational".to_string(),
                        description: None,
                    },
                ),
                (
                    "2".to_string(),
                    OcsfEnumValue {
                        caption: "Low".to_string(),
                        description: None,
                    },
                ),
                (
                    "3".to_string(),
                    OcsfEnumValue {
                        caption: "Medium".to_string(),
                        description: None,
                    },
                ),
                (
                    "4".to_string(),
                    OcsfEnumValue {
                        caption: "High".to_string(),
                        description: None,
                    },
                ),
                (
                    "5".to_string(),
                    OcsfEnumValue {
                        caption: "Critical".to_string(),
                        description: None,
                    },
                ),
                (
                    "6".to_string(),
                    OcsfEnumValue {
                        caption: "Fatal".to_string(),
                        description: None,
                    },
                ),
                (
                    "99".to_string(),
                    OcsfEnumValue {
                        caption: "Other".to_string(),
                        description: None,
                    },
                ),
            ])),
            ..default_attr()
        },
    );
    auth_attrs.insert(
        "src_endpoint".to_string(),
        OcsfAttribute {
            type_name: "object_t".to_string(),
            caption: "Source Endpoint".to_string(),
            object_type: Some("network_endpoint".to_string()),
            ..default_attr()
        },
    );
    auth_attrs.insert(
        "time".to_string(),
        OcsfAttribute {
            type_name: "timestamp_t".to_string(),
            caption: "Event Time".to_string(),
            ..default_attr()
        },
    );
    // OCSF defines `unmapped` as object_t referencing the base `object` type
    // (an empty object with zero attributes). The generator must emit `string`
    // instead of an empty Object message reference.
    auth_attrs.insert(
        "unmapped".to_string(),
        OcsfAttribute {
            type_name: "object_t".to_string(),
            caption: "Unmapped Data".to_string(),
            object_type: Some("object".to_string()),
            ..default_attr()
        },
    );
    // A deprecated field that should be skipped.
    auth_attrs.insert(
        "old_field".to_string(),
        OcsfAttribute {
            type_name: "string_t".to_string(),
            caption: "Old Field".to_string(),
            deprecated: Some(ocsf_proto_gen::schema::OcsfDeprecated {
                message: "Use new_field instead.".to_string(),
                since: "1.4.0".to_string(),
            }),
            ..default_attr()
        },
    );
    // A string-keyed enum that should NOT become a proto enum.
    auth_attrs.insert(
        "auth_protocol".to_string(),
        OcsfAttribute {
            type_name: "string_t".to_string(),
            caption: "Auth Protocol".to_string(),
            enum_values: Some(BTreeMap::from([
                (
                    "NTLM".to_string(),
                    OcsfEnumValue {
                        caption: "NTLM".to_string(),
                        description: None,
                    },
                ),
                (
                    "Kerberos".to_string(),
                    OcsfEnumValue {
                        caption: "Kerberos".to_string(),
                        description: None,
                    },
                ),
            ])),
            ..default_attr()
        },
    );
    auth_attrs.insert(
        "enrichments".to_string(),
        OcsfAttribute {
            type_name: "object_t".to_string(),
            caption: "Enrichments".to_string(),
            object_type: Some("enrichment".to_string()),
            is_array: true,
            ..default_attr()
        },
    );

    classes.insert(
        "authentication".to_string(),
        OcsfClass {
            name: "authentication".to_string(),
            uid: 3002,
            caption: "Authentication".to_string(),
            description: String::new(),
            extends: "iam".to_string(),
            category: "iam".to_string(),
            category_uid: 3,
            category_name: "Identity & Access Management".to_string(),
            profiles: vec![],
            attributes: auth_attrs,
        },
    );

    // NetworkEndpoint object.
    let mut ep_attrs = BTreeMap::new();
    ep_attrs.insert(
        "ip".to_string(),
        OcsfAttribute {
            type_name: "ip_t".to_string(),
            caption: "IP Address".to_string(),
            ..default_attr()
        },
    );
    ep_attrs.insert(
        "port".to_string(),
        OcsfAttribute {
            type_name: "port_t".to_string(),
            caption: "Port".to_string(),
            ..default_attr()
        },
    );
    ep_attrs.insert(
        "hostname".to_string(),
        OcsfAttribute {
            type_name: "hostname_t".to_string(),
            caption: "Hostname".to_string(),
            ..default_attr()
        },
    );
    ep_attrs.insert(
        "type_id".to_string(),
        OcsfAttribute {
            type_name: "integer_t".to_string(),
            caption: "Type ID".to_string(),
            enum_values: Some(BTreeMap::from([
                (
                    "0".to_string(),
                    OcsfEnumValue {
                        caption: "Unknown".to_string(),
                        description: None,
                    },
                ),
                (
                    "1".to_string(),
                    OcsfEnumValue {
                        caption: "Server".to_string(),
                        description: None,
                    },
                ),
                (
                    "2".to_string(),
                    OcsfEnumValue {
                        caption: "Desktop".to_string(),
                        description: None,
                    },
                ),
            ])),
            ..default_attr()
        },
    );
    objects.insert(
        "network_endpoint".to_string(),
        OcsfObject {
            name: "network_endpoint".to_string(),
            caption: "Network Endpoint".to_string(),
            description: String::new(),
            extends: None,
            attributes: ep_attrs,
            observable: Some(20),
        },
    );

    // Enrichment object (referenced as repeated).
    let mut enrich_attrs = BTreeMap::new();
    enrich_attrs.insert(
        "name".to_string(),
        OcsfAttribute {
            type_name: "string_t".to_string(),
            caption: "Name".to_string(),
            ..default_attr()
        },
    );
    enrich_attrs.insert(
        "value".to_string(),
        OcsfAttribute {
            type_name: "string_t".to_string(),
            caption: "Value".to_string(),
            ..default_attr()
        },
    );
    objects.insert(
        "enrichment".to_string(),
        OcsfObject {
            name: "enrichment".to_string(),
            caption: "Enrichment".to_string(),
            description: String::new(),
            extends: None,
            attributes: enrich_attrs,
            observable: None,
        },
    );

    // The base OCSF `object` type — an empty object definition.
    // Referenced by `unmapped` fields via object_type: "object".
    objects.insert(
        "object".to_string(),
        OcsfObject {
            name: "object".to_string(),
            caption: "Object".to_string(),
            description: String::new(),
            extends: None,
            attributes: BTreeMap::new(),
            observable: None,
        },
    );

    OcsfSchema {
        version: "1.7.0".to_string(),
        classes,
        objects,
        types: BTreeMap::new(),
        base_event: serde_json::Value::Null,
    }
}

fn default_attr() -> OcsfAttribute {
    OcsfAttribute {
        type_name: String::new(),
        caption: String::new(),
        description: String::new(),
        requirement: None,
        is_array: false,
        object_type: None,
        group: None,
        sibling: None,
        profile: None,
        enum_values: None,
        deprecated: None,
    }
}

#[test]
fn end_to_end_generate_and_validate() {
    let schema = test_schema();
    let dir = tempdir();

    let stats = codegen::generate(&schema, &["authentication".to_string()], &dir, Some(vec![]))
        .expect("generation should succeed");

    // Verify stats.
    assert_eq!(stats.classes_generated, 1);
    assert_eq!(stats.objects_generated, 3); // network_endpoint + enrichment + object (empty)
    assert!(stats.deprecated_fields_skipped >= 1);
    assert!(stats.enums_generated >= 2); // activity_id + severity_id + type_id

    // Verify files exist.
    let proto_dir = dir.join("ocsf/v1_7_0");
    assert!(proto_dir.join("events/iam/iam.proto").exists());
    assert!(proto_dir.join("events/iam/enums/enums.proto").exists());
    assert!(proto_dir.join("objects/objects.proto").exists());
    assert!(proto_dir.join("objects/enums/enums.proto").exists());
    assert!(proto_dir.join("enum-value-map.json").exists());
}

#[test]
fn generated_proto_has_correct_content() {
    let schema = test_schema();
    let dir = tempdir();

    codegen::generate(&schema, &["authentication".to_string()], &dir, Some(vec![])).unwrap();

    let proto = std::fs::read_to_string(dir.join("ocsf/v1_7_0/events/iam/iam.proto")).unwrap();

    // Verify proto3 syntax and package.
    assert!(proto.starts_with("syntax = \"proto3\";"));
    assert!(proto.contains("package ocsf.v1_7_0.events.iam;"));

    // Verify message name.
    assert!(proto.contains("message Authentication {"));

    // Verify enum type references (not primitive int32).
    assert!(proto.contains("ocsf.v1_7_0.events.iam.enums.AUTHENTICATION_ACTIVITY_ID activity_id"));
    assert!(proto.contains("ocsf.v1_7_0.events.iam.enums.AUTHENTICATION_SEVERITY_ID severity_id"));

    // Verify object references.
    assert!(proto.contains("ocsf.v1_7_0.objects.NetworkEndpoint src_endpoint"));
    assert!(proto.contains("repeated ocsf.v1_7_0.objects.Enrichment enrichments"));

    // Verify unmapped (object_t → empty object) maps to string, not an empty message.
    assert!(proto.contains("string unmapped"));
    assert!(!proto.contains("Object unmapped"));
    assert!(!proto.contains("google.protobuf.Struct"));

    // Verify deprecated field is skipped.
    assert!(!proto.contains("old_field"));

    // Verify string-keyed enum stays as string field (no enum type ref).
    assert!(proto.contains("string auth_protocol"));
    assert!(!proto.contains("AUTHENTICATION_AUTH_PROTOCOL"));

    // Verify imports.
    assert!(proto.contains("import \"ocsf/v1_7_0/events/iam/enums/enums.proto\";"));
    assert!(proto.contains("import \"ocsf/v1_7_0/objects/objects.proto\";"));
}

#[test]
fn generated_enums_have_correct_values() {
    let schema = test_schema();
    let dir = tempdir();

    codegen::generate(&schema, &["authentication".to_string()], &dir, Some(vec![])).unwrap();

    let enums =
        std::fs::read_to_string(dir.join("ocsf/v1_7_0/events/iam/enums/enums.proto")).unwrap();

    // Verify activity_id enum.
    assert!(enums.contains("enum AUTHENTICATION_ACTIVITY_ID {"));
    assert!(enums.contains("AUTHENTICATION_ACTIVITY_ID_UNKNOWN = 0;"));
    assert!(enums.contains("AUTHENTICATION_ACTIVITY_ID_LOGON = 1;"));
    assert!(enums.contains("AUTHENTICATION_ACTIVITY_ID_LOGOFF = 2;"));
    assert!(enums.contains("AUTHENTICATION_ACTIVITY_ID_OTHER = 99;"));

    // Verify severity_id enum.
    assert!(enums.contains("enum AUTHENTICATION_SEVERITY_ID {"));
    assert!(enums.contains("AUTHENTICATION_SEVERITY_ID_CRITICAL = 5;"));

    // Verify string-keyed enum is NOT generated.
    assert!(!enums.contains("AUTH_PROTOCOL"));

    // Verify object enums.
    let obj_enums =
        std::fs::read_to_string(dir.join("ocsf/v1_7_0/objects/enums/enums.proto")).unwrap();
    assert!(obj_enums.contains("enum NETWORK_ENDPOINT_TYPE_ID {"));
    assert!(obj_enums.contains("NETWORK_ENDPOINT_TYPE_ID_SERVER = 1;"));
}

#[test]
fn generated_objects_have_correct_fields() {
    let schema = test_schema();
    let dir = tempdir();

    codegen::generate(&schema, &["authentication".to_string()], &dir, Some(vec![])).unwrap();

    let objects = std::fs::read_to_string(dir.join("ocsf/v1_7_0/objects/objects.proto")).unwrap();

    // Verify network_endpoint message.
    assert!(objects.contains("message NetworkEndpoint {"));
    assert!(objects.contains("string hostname"));
    assert!(objects.contains("string ip"));
    assert!(objects.contains("int32 port"));
    // Verify object enum type reference.
    assert!(objects.contains("ocsf.v1_7_0.objects.enums.NETWORK_ENDPOINT_TYPE_ID type_id"));

    // Verify enrichment message.
    assert!(objects.contains("message Enrichment {"));
    assert!(objects.contains("string name"));
    assert!(objects.contains("string value"));
}

#[test]
fn enum_value_map_is_valid_json() {
    let schema = test_schema();
    let dir = tempdir();

    codegen::generate(&schema, &["authentication".to_string()], &dir, Some(vec![])).unwrap();

    let json_str = std::fs::read_to_string(dir.join("ocsf/v1_7_0/enum-value-map.json")).unwrap();
    let map: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    // Verify it's an object with enum entries.
    assert!(map.is_object());
    let obj = map.as_object().unwrap();
    assert!(obj.contains_key("AUTHENTICATION_ACTIVITY_ID_LOGON"));
    assert_eq!(obj["AUTHENTICATION_ACTIVITY_ID_LOGON"]["value"], 1);
    assert_eq!(obj["AUTHENTICATION_ACTIVITY_ID_LOGON"]["name"], "Logon");
}

#[test]
fn deterministic_output() {
    let schema = test_schema();

    let dir_a = tempdir();
    let dir_b = tempdir();

    codegen::generate(&schema, &["authentication".to_string()], &dir_a, Some(vec![])).unwrap();
    codegen::generate(&schema, &["authentication".to_string()], &dir_b, Some(vec![])).unwrap();

    // Compare all generated files byte-for-byte.
    for entry in walkdir(&dir_a) {
        let relative = entry.strip_prefix(&dir_a).unwrap();
        let file_a = std::fs::read_to_string(&entry).unwrap();
        let file_b = std::fs::read_to_string(dir_b.join(relative)).unwrap();
        assert_eq!(file_a, file_b, "files differ: {}", relative.display());
    }
}

#[test]
fn invalid_class_name_returns_error() {
    let schema = test_schema();
    let dir = tempdir();

    let result = codegen::generate(&schema, &["nonexistent_class".to_string()], &dir, Some(vec![]));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("nonexistent_class"));
    assert!(err.contains("not found"));
    // Should mention available classes.
    assert!(err.contains("authentication"));
}

#[test]
fn schema_load_from_file() {
    let dir = tempdir();
    let path = dir.join("schema.json");

    // Write a minimal schema JSON directly.
    std::fs::write(
        &path,
        r#"{"version":"1.7.0","classes":{},"objects":{},"types":{},"base_event":{}}"#,
    )
    .unwrap();

    let loaded = ocsf_proto_gen::schema::load_schema(&path).unwrap();
    assert_eq!(loaded.version, "1.7.0");
    assert_eq!(loaded.classes.len(), 0);
    assert_eq!(loaded.objects.len(), 0);
}

#[test]
fn empty_object_type_emits_string() {
    // An object_t referencing an object with zero attributes should emit
    // `string` instead of an empty proto message reference.
    let schema = test_schema();
    let dir = tempdir();

    codegen::generate(&schema, &["authentication".to_string()], &dir, Some(vec![])).unwrap();

    let proto = std::fs::read_to_string(dir.join("ocsf/v1_7_0/events/iam/iam.proto")).unwrap();

    // unmapped is object_t → "object" (empty) → must become string.
    assert!(
        proto.contains("string unmapped"),
        "expected `string unmapped`, got:\n{proto}"
    );
    assert!(
        !proto.contains("Object unmapped"),
        "empty object type should NOT produce message reference"
    );
}

// ── Helpers ────────────────────────────────────────────────────────────

fn tempdir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("ocsf-proto-gen-test-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    fn walk(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, files);
                } else {
                    files.push(path);
                }
            }
        }
    }
    walk(dir, &mut files);
    files.sort();
    files
}
