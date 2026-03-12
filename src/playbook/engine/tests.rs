use super::*;
use serde_json::json;

// ── Variable extraction ─────────────────────────────────────────────

#[test]
fn extract_var_refs_simple() {
    let refs = extract_var_refs("$inputs.query");
    assert_eq!(refs, vec!["$inputs.query"]);
}

#[test]
fn extract_var_refs_embedded() {
    let refs = extract_var_refs("search for $inputs.query on $inputs.site");
    assert_eq!(refs, vec!["$inputs.query", "$inputs.site"]);
}

#[test]
fn extract_var_refs_with_brackets() {
    let refs = extract_var_refs("$search.results[0].title");
    assert_eq!(refs, vec!["$search.results[0].title"]);
}

#[test]
fn extract_var_refs_no_vars() {
    let refs = extract_var_refs("no variables here");
    assert!(refs.is_empty());
}

#[test]
fn extract_var_refs_dollar_at_end() {
    let refs = extract_var_refs("cost is $");
    assert!(refs.is_empty());
}

// ── PlaybookContext::resolve_var ─────────────────────────────────────

#[test]
fn resolve_var_inputs() {
    let ctx = PlaybookContext::new(json!({"query": "rust", "count": 5}));
    assert_eq!(ctx.resolve_var("$inputs.query"), json!("rust"));
    assert_eq!(ctx.resolve_var("$inputs.count"), json!(5));
}

#[test]
fn resolve_var_step_result() {
    let mut ctx = PlaybookContext::new(json!({}));
    ctx.step_results.insert(
        "search".to_string(),
        json!({"web": {"results": [{"title": "Rust"}]}}),
    );
    assert_eq!(
        ctx.resolve_var("$search.web.results[0].title"),
        json!("Rust")
    );
}

#[test]
fn resolve_var_missing_step_returns_null() {
    let ctx = PlaybookContext::new(json!({}));
    assert_eq!(ctx.resolve_var("$missing.field"), Value::Null);
}

#[test]
fn resolve_var_missing_field_returns_null() {
    let ctx = PlaybookContext::new(json!({"query": "rust"}));
    assert_eq!(ctx.resolve_var("$inputs.nonexistent"), Value::Null);
}

#[test]
fn resolve_var_step_name_only() {
    let mut ctx = PlaybookContext::new(json!({}));
    ctx.step_results
        .insert("search".to_string(), json!({"data": 42}));
    assert_eq!(ctx.resolve_var("$search"), json!({"data": 42}));
}

// ── PlaybookContext::interpolate ─────────────────────────────────────

#[test]
fn interpolate_pure_reference() {
    let ctx = PlaybookContext::new(json!({"query": "rust"}));
    let result = ctx.interpolate(&json!("$inputs.query"));
    assert_eq!(result, json!("rust"));
}

#[test]
fn interpolate_embedded_reference() {
    let ctx = PlaybookContext::new(json!({"query": "rust"}));
    let result = ctx.interpolate(&json!("search for $inputs.query"));
    assert_eq!(result, json!("search for rust"));
}

#[test]
fn interpolate_object_recursion() {
    let ctx = PlaybookContext::new(json!({"q": "test", "n": 5}));
    let input = json!({"query": "$inputs.q", "count": "$inputs.n"});
    let result = ctx.interpolate(&input);
    assert_eq!(result, json!({"query": "test", "count": 5}));
}

#[test]
fn interpolate_array_recursion() {
    let ctx = PlaybookContext::new(json!({"a": 1, "b": 2}));
    let input = json!(["$inputs.a", "$inputs.b"]);
    let result = ctx.interpolate(&input);
    assert_eq!(result, json!([1, 2]));
}

#[test]
fn interpolate_non_string_passthrough() {
    let ctx = PlaybookContext::new(json!({}));
    assert_eq!(ctx.interpolate(&json!(42)), json!(42));
    assert_eq!(ctx.interpolate(&json!(true)), json!(true));
    assert_eq!(ctx.interpolate(&Value::Null), Value::Null);
}

#[test]
fn interpolate_preserves_number_type() {
    let ctx = PlaybookContext::new(json!({"count": 5}));
    let result = ctx.interpolate(&json!("$inputs.count"));
    // Pure reference should preserve the number type
    assert_eq!(result, json!(5));
}

// ── evaluate_condition ──────────────────────────────────────────────

#[test]
fn condition_truthy_string() {
    let ctx = PlaybookContext::new(json!({"query": "rust"}));
    assert!(evaluate_condition("$inputs.query", &ctx));
}

#[test]
fn condition_falsy_null() {
    let ctx = PlaybookContext::new(json!({"query": null}));
    assert!(!evaluate_condition("$inputs.query", &ctx));
}

#[test]
fn condition_falsy_empty_string() {
    let ctx = PlaybookContext::new(json!({"query": ""}));
    assert!(!evaluate_condition("$inputs.query", &ctx));
}

#[test]
fn condition_equality_match() {
    let ctx = PlaybookContext::new(json!({"depth": "thorough"}));
    assert!(evaluate_condition("$inputs.depth == 'thorough'", &ctx));
}

#[test]
fn condition_equality_mismatch() {
    let ctx = PlaybookContext::new(json!({"depth": "quick"}));
    assert!(!evaluate_condition("$inputs.depth == 'thorough'", &ctx));
}

#[test]
fn condition_length_greater_than() {
    let mut ctx = PlaybookContext::new(json!({}));
    ctx.step_results.insert(
        "search".to_string(),
        json!({"web": {"results": [1, 2, 3]}}),
    );
    assert!(evaluate_condition(
        "$search.web.results | length > 0",
        &ctx
    ));
    assert!(!evaluate_condition(
        "$search.web.results | length > 5",
        &ctx
    ));
}

#[test]
fn condition_length_empty_array() {
    let mut ctx = PlaybookContext::new(json!({}));
    ctx.step_results
        .insert("search".to_string(), json!({"results": []}));
    assert!(!evaluate_condition(
        "$search.results | length > 0",
        &ctx
    ));
}

#[test]
fn condition_truthy_array() {
    let mut ctx = PlaybookContext::new(json!({}));
    ctx.step_results
        .insert("s".to_string(), json!({"items": [1]}));
    assert!(evaluate_condition("$s.items", &ctx));
}

#[test]
fn condition_falsy_empty_array() {
    let mut ctx = PlaybookContext::new(json!({}));
    ctx.step_results
        .insert("s".to_string(), json!({"items": []}));
    assert!(!evaluate_condition("$s.items", &ctx));
}

// ── is_truthy ───────────────────────────────────────────────────────

#[test]
fn truthy_values() {
    assert!(is_truthy(&json!(true)));
    assert!(is_truthy(&json!(1)));
    assert!(is_truthy(&json!("hello")));
    assert!(is_truthy(&json!([1])));
    assert!(is_truthy(&json!({"k": "v"})));
}

#[test]
fn falsy_values() {
    assert!(!is_truthy(&Value::Null));
    assert!(!is_truthy(&json!(false)));
    assert!(!is_truthy(&json!(0)));
    assert!(!is_truthy(&json!("")));
    assert!(!is_truthy(&json!([])));
    assert!(!is_truthy(&json!({})));
}

// ── PlaybookEngine ──────────────────────────────────────────────────

#[test]
fn engine_new_is_empty() {
    let engine = PlaybookEngine::new();
    assert!(engine.is_empty());
    assert_eq!(engine.len(), 0);
}

#[test]
fn engine_register_and_get() {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "test".to_string(),
        description: "A test playbook".to_string(),
        inputs: json!({}),
        steps: vec![],
        output: None,
        on_error: ErrorStrategy::Abort,
        max_retries: 1,
        timeout: 60,
    });
    assert_eq!(engine.len(), 1);
    assert!(engine.get("test").is_some());
    assert!(engine.get("missing").is_none());
    assert_eq!(engine.list(), vec!["test"]);
}

// ── PlaybookEngine::execute (with mock invoker) ─────────────────────

struct MockInvoker {
    responses: HashMap<String, Value>,
}

impl MockInvoker {
    fn new() -> Self {
        Self {
            responses: HashMap::new(),
        }
    }

    fn respond(mut self, tool: &str, response: Value) -> Self {
        self.responses.insert(tool.to_string(), response);
        self
    }
}

#[async_trait::async_trait]
impl ToolInvoker for MockInvoker {
    async fn invoke(
        &self,
        _server: &str,
        tool: &str,
        _arguments: Value,
    ) -> crate::Result<Value> {
        self.responses
            .get(tool)
            .cloned()
            .ok_or_else(|| crate::Error::Internal(format!("Mock: tool not found: {tool}")))
    }
}

#[tokio::test]
async fn execute_simple_playbook() {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "simple".to_string(),
        description: "Simple test".to_string(),
        inputs: json!({}),
        steps: vec![PlaybookStep {
            name: "step1".to_string(),
            tool: "my_tool".to_string(),
            server: "test".to_string(),
            arguments: HashMap::from([("q".to_string(), json!("hello"))]),
            condition: None,
        }],
        output: None,
        on_error: ErrorStrategy::Abort,
        max_retries: 1,
        timeout: 60,
    });

    let invoker = MockInvoker::new().respond("my_tool", json!({"result": "world"}));
    let result = engine.execute("simple", json!({}), &invoker).await.unwrap();
    assert_eq!(result.steps_completed, vec!["step1"]);
    assert!(result.steps_failed.is_empty());
    assert_eq!(result.output["step1"], json!({"result": "world"}));
}

#[tokio::test]
async fn execute_with_variable_interpolation() {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "interp".to_string(),
        description: "Interpolation test".to_string(),
        inputs: json!({}),
        steps: vec![
            PlaybookStep {
                name: "search".to_string(),
                tool: "brave_search".to_string(),
                server: "cap".to_string(),
                arguments: HashMap::from([("query".to_string(), json!("$inputs.query"))]),
                condition: None,
            },
            PlaybookStep {
                name: "ground".to_string(),
                tool: "brave_grounding".to_string(),
                server: "cap".to_string(),
                arguments: HashMap::from([(
                    "query".to_string(),
                    json!("$search.top_result"),
                )]),
                condition: None,
            },
        ],
        output: Some(PlaybookOutput {
            output_type: "object".to_string(),
            properties: HashMap::from([
                (
                    "answer".to_string(),
                    OutputMapping {
                        path: "$ground.answer".to_string(),
                        fallback: Some(json!("No answer")),
                    },
                ),
                (
                    "query".to_string(),
                    OutputMapping {
                        path: "$search.top_result".to_string(),
                        fallback: None,
                    },
                ),
            ]),
        }),
        on_error: ErrorStrategy::Abort,
        max_retries: 1,
        timeout: 60,
    });

    let invoker = MockInvoker::new()
        .respond("brave_search", json!({"top_result": "Rust Language"}))
        .respond("brave_grounding", json!({"answer": "Rust is great"}));

    let result = engine
        .execute("interp", json!({"query": "Rust"}), &invoker)
        .await
        .unwrap();

    assert_eq!(result.steps_completed, vec!["search", "ground"]);
    assert_eq!(result.output["answer"], json!("Rust is great"));
    assert_eq!(result.output["query"], json!("Rust Language"));
}

#[tokio::test]
async fn execute_with_condition_skip() {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "cond".to_string(),
        description: "Condition test".to_string(),
        inputs: json!({}),
        steps: vec![
            PlaybookStep {
                name: "always".to_string(),
                tool: "tool_a".to_string(),
                server: "s".to_string(),
                arguments: HashMap::new(),
                condition: None,
            },
            PlaybookStep {
                name: "conditional".to_string(),
                tool: "tool_b".to_string(),
                server: "s".to_string(),
                arguments: HashMap::new(),
                condition: Some("$inputs.deep == 'true'".to_string()),
            },
        ],
        output: None,
        on_error: ErrorStrategy::Abort,
        max_retries: 1,
        timeout: 60,
    });

    let invoker = MockInvoker::new()
        .respond("tool_a", json!({"ok": true}))
        .respond("tool_b", json!({"deep": true}));

    // With condition false
    let result = engine
        .execute("cond", json!({"deep": "false"}), &invoker)
        .await
        .unwrap();
    assert_eq!(result.steps_completed, vec!["always"]);
    assert_eq!(result.steps_skipped, vec!["conditional"]);

    // With condition true
    let result = engine
        .execute("cond", json!({"deep": "true"}), &invoker)
        .await
        .unwrap();
    assert_eq!(result.steps_completed, vec!["always", "conditional"]);
    assert!(result.steps_skipped.is_empty());
}

#[tokio::test]
async fn execute_abort_on_error() {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "abort_test".to_string(),
        description: "Abort test".to_string(),
        inputs: json!({}),
        steps: vec![
            PlaybookStep {
                name: "fail".to_string(),
                tool: "nonexistent".to_string(),
                server: "s".to_string(),
                arguments: HashMap::new(),
                condition: None,
            },
            PlaybookStep {
                name: "never_reached".to_string(),
                tool: "tool_a".to_string(),
                server: "s".to_string(),
                arguments: HashMap::new(),
                condition: None,
            },
        ],
        output: None,
        on_error: ErrorStrategy::Abort,
        max_retries: 1,
        timeout: 60,
    });

    let invoker = MockInvoker::new().respond("tool_a", json!({"ok": true}));
    let err = engine
        .execute("abort_test", json!({}), &invoker)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
}

#[tokio::test]
async fn execute_continue_on_error() {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "continue_test".to_string(),
        description: "Continue test".to_string(),
        inputs: json!({}),
        steps: vec![
            PlaybookStep {
                name: "fail".to_string(),
                tool: "nonexistent".to_string(),
                server: "s".to_string(),
                arguments: HashMap::new(),
                condition: None,
            },
            PlaybookStep {
                name: "after_fail".to_string(),
                tool: "tool_a".to_string(),
                server: "s".to_string(),
                arguments: HashMap::new(),
                condition: None,
            },
        ],
        output: None,
        on_error: ErrorStrategy::Continue,
        max_retries: 1,
        timeout: 60,
    });

    let invoker = MockInvoker::new().respond("tool_a", json!({"ok": true}));
    let result = engine
        .execute("continue_test", json!({}), &invoker)
        .await
        .unwrap();
    assert_eq!(result.steps_failed, vec!["fail"]);
    assert_eq!(result.steps_completed, vec!["after_fail"]);
}

#[tokio::test]
async fn execute_output_with_fallback() {
    let mut engine = PlaybookEngine::new();
    engine.register(PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "fallback_test".to_string(),
        description: "Fallback test".to_string(),
        inputs: json!({}),
        steps: vec![PlaybookStep {
            name: "step1".to_string(),
            tool: "tool_a".to_string(),
            server: "s".to_string(),
            arguments: HashMap::new(),
            condition: None,
        }],
        output: Some(PlaybookOutput {
            output_type: "object".to_string(),
            properties: HashMap::from([
                (
                    "found".to_string(),
                    OutputMapping {
                        path: "$step1.data".to_string(),
                        fallback: None,
                    },
                ),
                (
                    "missing".to_string(),
                    OutputMapping {
                        path: "$step1.nonexistent".to_string(),
                        fallback: Some(json!("default_value")),
                    },
                ),
                (
                    "null_no_fallback".to_string(),
                    OutputMapping {
                        path: "$step1.nonexistent".to_string(),
                        fallback: None,
                    },
                ),
            ]),
        }),
        on_error: ErrorStrategy::Abort,
        max_retries: 1,
        timeout: 60,
    });

    let invoker = MockInvoker::new().respond("tool_a", json!({"data": "found_it"}));
    let result = engine
        .execute("fallback_test", json!({}), &invoker)
        .await
        .unwrap();

    assert_eq!(result.output["found"], json!("found_it"));
    assert_eq!(result.output["missing"], json!("default_value"));
    assert_eq!(result.output["null_no_fallback"], Value::Null);
}

#[tokio::test]
async fn execute_playbook_not_found() {
    let engine = PlaybookEngine::new();
    let invoker = MockInvoker::new();
    let err = engine
        .execute("nonexistent", json!({}), &invoker)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Playbook not found"));
}

// ── YAML deserialization ────────────────────────────────────────────

#[test]
fn deserialize_playbook_from_yaml() {
    let yaml = r#"
playbook: "1.0"
name: research_topic
description: Search and ground a topic
inputs:
  type: object
  properties:
query:
  type: string
  required: [query]
steps:
  - name: search
tool: brave_search
server: capabilities
arguments:
  query: "$inputs.query"
  count: 5
  - name: ground
tool: brave_grounding
server: capabilities
arguments:
  query: "$search.web.results[0].title"
condition: "$search.web.results | length > 0"
output:
  type: object
  properties:
summary:
  path: "$ground.answer"
  fallback: "No grounding available"
sources:
  path: "$search.web.results[].url"
on_error: continue
max_retries: 2
timeout: 30
"#;
    let def: PlaybookDefinition = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(def.name, "research_topic");
    assert_eq!(def.steps.len(), 2);
    assert_eq!(def.steps[0].name, "search");
    assert_eq!(def.steps[1].condition, Some("$search.web.results | length > 0".to_string()));
    assert!(def.output.is_some());
    assert_eq!(def.on_error, ErrorStrategy::Continue);
    assert_eq!(def.max_retries, 2);
    assert_eq!(def.timeout, 30);
}

#[test]
fn deserialize_minimal_playbook() {
    let yaml = r"
name: minimal
description: Minimal playbook
steps:
  - name: step1
tool: some_tool
";
    let def: PlaybookDefinition = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(def.name, "minimal");
    assert_eq!(def.playbook, "1.0");
    assert_eq!(def.on_error, ErrorStrategy::Abort);
    assert_eq!(def.max_retries, 1);
    assert_eq!(def.timeout, 60);
    assert_eq!(def.steps[0].server, "capabilities");
}

// ── build_output ────────────────────────────────────────────────────

#[test]
fn build_output_no_mapping_returns_all_results() {
    let def = PlaybookDefinition {
        playbook: "1.0".to_string(),
        name: "test".to_string(),
        description: "test".to_string(),
        inputs: json!({}),
        steps: vec![],
        output: None,
        on_error: ErrorStrategy::Abort,
        max_retries: 1,
        timeout: 60,
    };
    let mut ctx = PlaybookContext::new(json!({}));
    ctx.step_results
        .insert("s1".to_string(), json!({"data": 1}));

    let output = build_output(&def, &ctx);
    assert_eq!(output["s1"], json!({"data": 1}));
}
