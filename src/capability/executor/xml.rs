//! XML-to-JSON conversion helpers
//!
//! The mapping is intentionally simple and lossless:
//!
//! - Each element becomes a JSON object keyed by its local name (namespace
//!   prefixes are stripped).
//! - XML attributes are stored as string fields prefixed with `@` (e.g.
//!   `@currency`, `@rate`).
//! - Text content (CDATA / character data) is stored under the `#text` key.
//! - Repeated child elements with the same name are collected into a JSON
//!   array.
//!
//! This is sufficient for common structured XML APIs like the ECB exchange
//! rate feed while avoiding a heavyweight XML-to-JSON library.

use serde_json::Value;

/// Convert an XML string into a `serde_json::Value`.
pub(super) fn xml_to_json(xml: &str) -> std::result::Result<Value, String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);

    // Stack of (element_name, json_object) pairs.
    let mut stack: Vec<(String, serde_json::Map<String, Value>)> = Vec::new();
    // Push a synthetic root so we always have a target.
    stack.push(("_root".to_string(), serde_json::Map::new()));

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = local_name(e.name().as_ref());
                let mut obj = serde_json::Map::new();

                // Collect attributes
                for attr in e.attributes().flatten() {
                    let key = format!("@{}", local_name(attr.key.as_ref()));
                    let val = String::from_utf8_lossy(&attr.value).to_string();
                    obj.insert(key, Value::String(val));
                }

                stack.push((name, obj));
            }
            Ok(Event::Empty(ref e)) => {
                // Self-closing element, e.g. <Cube currency='USD' rate='1.05'/>
                let name = local_name(e.name().as_ref());
                let mut obj = serde_json::Map::new();

                for attr in e.attributes().flatten() {
                    let key = format!("@{}", local_name(attr.key.as_ref()));
                    let val = String::from_utf8_lossy(&attr.value).to_string();
                    obj.insert(key, Value::String(val));
                }

                // Attach to parent
                if let Some(parent) = stack.last_mut() {
                    insert_child(&mut parent.1, &name, Value::Object(obj));
                }
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().trim().to_string();
                if !text.is_empty() {
                    if let Some(current) = stack.last_mut() {
                        current
                            .1
                            .insert("#text".to_string(), Value::String(text));
                    }
                }
            }
            Ok(Event::CData(ref e)) => {
                let text = String::from_utf8_lossy(e.as_ref()).trim().to_string();
                if !text.is_empty() {
                    if let Some(current) = stack.last_mut() {
                        current
                            .1
                            .insert("#text".to_string(), Value::String(text));
                    }
                }
            }
            Ok(Event::End(_)) => {
                if let Some((name, obj)) = stack.pop() {
                    let value = Value::Object(obj);
                    if let Some(parent) = stack.last_mut() {
                        insert_child(&mut parent.1, &name, value);
                    } else {
                        // Should not happen (we have a synthetic root), but
                        // return what we have.
                        return Ok(value);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {} // Skip comments, processing instructions, etc.
            Err(e) => {
                return Err(format!(
                    "XML parse error at position {}: {e}",
                    reader.error_position()
                ));
            }
        }
    }

    // Unwrap the synthetic root.  If it has a single child, return that
    // child directly (common case: the XML has one root element).
    let (_, root_obj) = stack.pop().unwrap_or_default();
    if root_obj.len() == 1 {
        Ok(root_obj.into_values().next().unwrap_or(Value::Null))
    } else {
        Ok(Value::Object(root_obj))
    }
}

/// Insert a child value into a parent JSON object, converting to an array
/// when a key is repeated (e.g. multiple `<Cube>` elements).
fn insert_child(parent: &mut serde_json::Map<String, Value>, key: &str, value: Value) {
    use serde_json::map::Entry;

    match parent.entry(key.to_string()) {
        Entry::Vacant(e) => {
            e.insert(value);
        }
        Entry::Occupied(mut e) => {
            let existing = e.get_mut();
            match existing {
                Value::Array(arr) => arr.push(value),
                _ => {
                    let prev = existing.take();
                    *existing = Value::Array(vec![prev, value]);
                }
            }
        }
    }
}

/// Extract the local name from a (possibly namespace-prefixed) XML tag.
///
/// E.g. `gesmes:Envelope` -> `Envelope`, `Cube` -> `Cube`.
fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    match s.rfind(':') {
        Some(i) => s[i + 1..].to_string(),
        None => s.to_string(),
    }
}
