use once_cell::sync::OnceCell;
use reqwest::blocking as reqwest_blocking;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::{Child, Command as StdCommand};
use std::sync::Arc;

static GLOBAL: OnceCell<Arc<VardenGuard>> = OnceCell::new();

#[derive(Debug, Clone)]
pub struct VardenConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub app_name: String,
    pub tenant: String,
    pub mode: String,
    pub fail_mode: String,
    pub timeout_secs: u64,
}

impl Default for VardenConfig {
    fn default() -> Self {
        Self {
            base_url: std::env::var("VARDEN_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8000".to_string()),
            api_key: std::env::var("VARDEN_API_KEY").ok(),
            app_name: std::env::var("VARDEN_APP_NAME").unwrap_or_else(|_| "rust-app".to_string()),
            tenant: "default".to_string(),
            mode: std::env::var("VARDEN_MODE").unwrap_or_else(|_| "enforce".to_string()),
            fail_mode: std::env::var("VARDEN_FAIL_MODE").unwrap_or_else(|_| "open".to_string()),
            timeout_secs: std::env::var("VARDEN_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(5),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("varden blocked action")]
    Blocked(GuardResult),
    #[error("varden not initialized")]
    NotInitialized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub action: String,
    pub reason: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardResult {
    pub decision: Decision,
    pub action: Value,
    pub event_id: Option<i64>,
}

#[derive(Debug)]
pub struct VardenGuard {
    cfg: VardenConfig,
    http: reqwest_blocking::Client,
}

impl VardenGuard {
    pub fn new(mut cfg: VardenConfig) -> Result<Self, Error> {
        let http = reqwest_blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
            .build()?;
        if cfg.api_key.is_none() {
            let bootstrap: Value = http
                .get(format!("{}/sdk/bootstrap", cfg.base_url.trim_end_matches('/')))
                .send()?
                .error_for_status()?
                .json()?;
            cfg.api_key = bootstrap.get("bootstrap_api_key").and_then(|v| v.as_str()).map(ToString::to_string);
        }
        Ok(Self { cfg, http })
    }

    pub fn guard(&self, action: Value, payload: Value) -> Result<GuardResult, Error> {
        let mut request = self.http.post(format!("{}/sdk/guard", self.cfg.base_url.trim_end_matches('/'))).json(&json!({
            "action": action,
            "payload": payload,
        }));
        if let Some(key) = &self.cfg.api_key {
            request = request.header("x-api-key", key);
        }
        let response = request.send()?;
        if response.status().as_u16() == 403 {
            let result: GuardResult = response.json()?;
            return Err(Error::Blocked(result));
        }
        Ok(response.error_for_status()?.json()?)
    }

    pub fn action(&self, typ: &str, tool: &str, args: Value, metadata: Value, payload: Value) -> Result<GuardResult, Error> {
        self.guard(json!({
            "type": typ,
            "tool": tool,
            "args": args,
            "metadata": {
                "app_name": self.cfg.app_name,
                "tenant": self.cfg.tenant,
                "execution_surface": metadata.get("execution_surface").cloned().unwrap_or(json!(null)),
            },
            "tenant_id": self.cfg.tenant,
        }), payload)
    }
}

pub fn protect() -> Result<(), Error> {
    protect_with(VardenConfig::default())
}

pub fn protect_with(cfg: VardenConfig) -> Result<(), Error> {
    let guard = Arc::new(VardenGuard::new(cfg)?);
    let _ = GLOBAL.set(guard);
    Ok(())
}

pub fn current() -> Result<Arc<VardenGuard>, Error> {
    GLOBAL.get().cloned().ok_or(Error::NotInitialized)
}

pub fn guard<T, F>(tool: &str, payload: Value, action: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
{
    let varden = current()?;
    varden.action("tool_call", tool, payload.clone(), json!({"execution_surface": "rust-guard"}), payload)?;
    action()
}

#[macro_export]
macro_rules! guard {
    ($tool:expr, $payload:expr, $body:block) => {{
        varden::guard($tool, $payload, || $body)
    }};
}

pub mod http {
    use super::*;

    pub struct Client {
        inner: reqwest_blocking::Client,
        varden: Arc<VardenGuard>,
    }

    impl Client {
        pub fn new() -> Result<Self, Error> {
            Ok(Self {
                inner: reqwest_blocking::Client::new(),
                varden: current()?,
            })
        }

        pub fn get(&self, url: &str) -> Result<reqwest_blocking::Response, Error> {
            self.varden.action(
                "http_request",
                "reqwest::blocking::Client",
                json!({"method": "GET", "url": url}),
                json!({"execution_surface": "rust-http"}),
                json!({"method": "GET", "url": url}),
            )?;
            Ok(self.inner.get(url).send()?)
        }

        pub fn post_json(&self, url: &str, body: Value) -> Result<reqwest_blocking::Response, Error> {
            self.varden.action(
                "http_request",
                "reqwest::blocking::Client",
                json!({"method": "POST", "url": url, "body": body}),
                json!({"execution_surface": "rust-http"}),
                json!({"method": "POST", "url": url, "body": body}),
            )?;
            Ok(self.inner.post(url).json(&body).send()?)
        }
    }
}

pub mod process {
    use super::*;

    pub struct Command {
        inner: StdCommand,
        original: Vec<String>,
        varden: Arc<VardenGuard>,
    }

    impl Command {
        pub fn new(program: impl Into<String>) -> Result<Self, Error> {
            let program = program.into();
            Ok(Self {
                inner: StdCommand::new(&program),
                original: vec![program],
                varden: current()?,
            })
        }

        pub fn arg(mut self, arg: impl Into<String>) -> Self {
            let arg = arg.into();
            self.inner.arg(&arg);
            self.original.push(arg);
            self
        }

        pub fn spawn(mut self) -> Result<Child, Error> {
            self.varden.action(
                "tool_call",
                "std::process::Command",
                json!({"command": self.original}),
                json!({"execution_surface": "rust-process"}),
                json!({"command": self.original}),
            )?;
            Ok(self.inner.spawn()?)
        }
    }
}
