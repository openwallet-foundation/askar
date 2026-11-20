//! An MCP (Model Context Protocol) server over stdio that forwards to the agent API.
//!
//! It holds no keys and no data: every tool call becomes a request to the agent API, which
//! applies the redacted view. Agents can only leave proposals for a person to review.

use std::path::PathBuf;

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_TEXT: usize = 100_000;

const INSTRUCTIONS: &str = "This server gives a redacted view of an encrypted Askar store. \
You can see its structure, counts and patterns, but never secret values: values appear as \
shapes such as <string:12>, names and most tag values as pseudonyms such as p-3fa9c1d07b2e \
(equal values get equal pseudonyms), and key material is never shown. Start with \
category_stats, then describe_category, then query. You cannot change data. When a change is \
needed, use propose_change: it saves a proposal that a person reviews, with the real values, \
and applies or rejects. Edit entries by profile name and id (as listed by list_entries); give \
clear titles and reasons, then tell the person the review command that the tool returns.";

/// Where the bearer token comes from.
#[derive(Clone, Debug)]
pub enum Token {
    /// A fixed token.
    Literal(String),
    /// A file read on every request, so a restarted server's new token is picked up.
    File(PathBuf),
}

impl Token {
    fn read(&self) -> Result<String> {
        match self {
            Self::Literal(token) => Ok(token.clone()),
            Self::File(path) => Ok(std::fs::read_to_string(path)
                .with_context(|| format!("Cannot read the agent token at {}", path.display()))?
                .trim()
                .to_owned()),
        }
    }
}

enum Http {
    Get,
    Post,
}

struct Tool {
    name: &'static str,
    description: &'static str,
    http: Http,
    path: &'static str,
    schema: fn() -> Value,
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": properties, "required": required, "additionalProperties": false })
}

const TOOLS: [Tool; 8] = [
    Tool {
        name: "list_profiles",
        description: "List the profiles in the store and whether their keys unlocked.",
        http: Http::Get,
        path: "/v1/profiles",
        schema: || object(json!({}), &[]),
    },
    Tool {
        name: "category_stats",
        description: "Count entries, expired entries and encrypted bytes for each category. \
Start here to see what the store holds.",
        http: Http::Get,
        path: "/v1/stats",
        schema: || {
            object(
                json!({ "profile": {"type": "string", "description": "Only this profile"} }),
                &[],
            )
        },
    },
    Tool {
        name: "describe_category",
        description: "Summarize the structure of one category from a sample of its entries: \
JSON paths with their types, how often each appears, distinct counts, string lengths and tag \
usage. Real values are shown only where the operator's policy allows it.",
        http: Http::Post,
        path: "/v1/describe",
        schema: || {
            object(
                json!({
                    "category": {"type": "string"},
                    "profile": {"type": "string"},
                    "sample": {"type": "integer", "minimum": 1, "maximum": 5000, "description": "Entries to inspect, in id order (default 500)"}
                }),
                &["category"],
            )
        },
    },
    Tool {
        name: "query",
        description: "Run one read-only SQL SELECT (SQLite syntax) on the table `items`. Columns: \
profile, id, kind ('item' or 'kms'), category, name (a pseudonym), value (the JSON shape of the \
value, as text; use json_extract(value, '$.path')), value_bytes, expiry, ptags and etags (JSON \
objects of tag values), errors. Filters of the form category = 'x', kind = 'item', id = 5, \
profile = 'p' and ptag = 'name=value' (for tags the policy lists) are evaluated by the database \
and are fast; other conditions scan the category, so combine them with a category filter.",
        http: Http::Post,
        path: "/v1/query",
        schema: || {
            object(
                json!({
                    "sql": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Maximum rows (default 200)"}
                }),
                &["sql"],
            )
        },
    },
    Tool {
        name: "list_entries",
        description: "List entries with their redacted values, optionally filtered by category, \
kind, expiry and tags the operator's policy lists. Pages by id: pass the last id as after_id.",
        http: Http::Post,
        path: "/v1/entries",
        schema: || {
            object(
                json!({
                    "profile": {"type": "string"},
                    "category": {"type": "string"},
                    "kind": {"type": "string", "enum": ["item", "kms", "any"]},
                    "expiry": {"type": "string", "enum": ["any", "live", "expired"]},
                    "tags": {"type": "array", "items": {"type": "string"}, "description": "Encrypted tags as name=value"},
                    "plaintext_tags": {"type": "array", "items": {"type": "string"}, "description": "Plaintext tags as name=value"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                    "after_id": {"type": "integer"}
                }),
                &[],
            )
        },
    },
    Tool {
        name: "get_entry",
        description: "Show one entry by id, with its redacted value and tags.",
        http: Http::Post,
        path: "/v1/entry",
        schema: || {
            object(
                json!({ "id": {"type": "integer"}, "profile": {"type": "string"} }),
                &["id"],
            )
        },
    },
    Tool {
        name: "propose_change",
        description: "Propose edits for a person to review. Nothing is changed: the proposal is \
saved, and a person sees the real before and after and decides. Each op names a profile and an \
entry id (from list_entries) and has an \"op\": set_json (with \"pointer\", an RFC 6901 JSON \
Pointer such as /state, and \"value\"), set_tag (\"name\", \"value\", optional \"plaintext\"), \
remove_tag (\"name\", optional \"plaintext\"), set_expiry (\"expiry\" such as 2030-01-01 00:00:00, or null), remove, \
or insert (\"category\", \"name\", \"value\", optional \"tags\"; no id). You will not be told \
whether an edit would change anything, so base proposals on what you observed.",
        http: Http::Post,
        path: "/v1/proposals",
        schema: || {
            object(
                json!({
                    "title": {"type": "string", "description": "Short summary for the reviewer"},
                    "rationale": {"type": "string", "description": "Why the change is wanted"},
                    "ops": {
                        "type": "array",
                        "maxItems": 100,
                        "items": {"type": "object", "required": ["op"], "properties": {"op": {"type": "string", "enum": ["set_json", "set_tag", "remove_tag", "set_expiry", "remove", "insert"]}}}
                    }
                }),
                &["title", "ops"],
            )
        },
    },
    Tool {
        name: "list_proposals",
        description: "List proposals with their status: pending, applied or rejected.",
        http: Http::Get,
        path: "/v1/proposals",
        schema: || object(json!({}), &[]),
    },
];

fn tool_list() -> Value {
    json!({ "tools": TOOLS.iter().map(|tool| json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": (tool.schema)(),
    })).collect::<Vec<_>>() })
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_result(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn tool_result(text: String, is_error: bool) -> Value {
    let text = if text.chars().count() > MAX_TEXT {
        let kept: String = text.chars().take(MAX_TEXT).collect();
        format!("{kept}\n[output cut at {MAX_TEXT} characters; narrow the request]")
    } else {
        text
    };
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

/// The proxy's connection to the agent API.
pub struct Proxy {
    client: Client,
    base: String,
    token: Token,
}

impl Proxy {
    /// Forward to the agent API at `base`.
    pub fn new(base: &str, token: Token) -> Self {
        Self {
            client: Client::new(),
            base: base.trim_end_matches('/').to_owned(),
            token,
        }
    }

    async fn call(&self, tool: &Tool, arguments: Value) -> Value {
        let token = match self.token.read() {
            Ok(token) => token,
            Err(error) => return tool_result(format!("{error:#}"), true),
        };
        let url = format!("{}{}", self.base, tool.path);
        let request = match tool.http {
            Http::Get => {
                let params: Vec<(String, String)> = arguments
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|text| (key.clone(), text.to_owned()))
                    })
                    .collect();
                self.client.get(url).query(&params)
            }
            Http::Post => self.client.post(url).json(&arguments),
        };
        let response = match request.bearer_auth(token).send().await {
            Ok(response) => response,
            Err(error) => {
                return tool_result(
                    format!("Cannot reach the explorer at {}: {error}", self.base),
                    true,
                )
            }
        };
        let status = response.status();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            tool_result(body.to_string(), false)
        } else {
            let message = body["error"]
                .as_str()
                .map_or_else(|| status.to_string(), str::to_owned);
            tool_result(message, true)
        }
    }

    /// Handle one JSON-RPC message; `None` means no reply is due.
    pub async fn handle(&self, message: &Value) -> Option<Value> {
        let id = message.get("id");
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return id.map(|id| rpc_error(id, -32600, "Invalid request"));
        };
        let Some(id) = id else {
            return None; // notifications such as notifications/initialized
        };
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        Some(match method {
            "initialize" => {
                let asked = params["protocolVersion"].as_str().unwrap_or_default();
                let version = VERSIONS
                    .iter()
                    .find(|version| **version == asked)
                    .unwrap_or(&VERSIONS[0]);
                rpc_result(
                    id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "askar-explorer", "version": env!("CARGO_PKG_VERSION") },
                        "instructions": INSTRUCTIONS,
                    }),
                )
            }
            "ping" => rpc_result(id, json!({})),
            "tools/list" => rpc_result(id, tool_list()),
            "tools/call" => {
                let Some(tool) = params["name"]
                    .as_str()
                    .and_then(|name| TOOLS.iter().find(|tool| tool.name == name))
                else {
                    return Some(rpc_error(id, -32602, "Unknown tool"));
                };
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if !arguments.is_object() {
                    return Some(rpc_error(id, -32602, "Tool arguments must be an object"));
                }
                rpc_result(id, self.call(tool, arguments).await)
            }
            _ => rpc_error(id, -32601, "Method not found"),
        })
    }
}

/// Serve MCP on stdin and stdout until stdin closes.
pub async fn run(base: &str, token: Token) -> Result<()> {
    let proxy = Proxy::new(base, token);
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => proxy.handle(&message).await,
            Err(_) => Some(rpc_error(&Value::Null, -32700, "Parse error")),
        };
        if let Some(reply) = reply {
            stdout.write_all(reply.to_string().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}
