use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const WATCH_ALERT_SCHEMA: &str = "morph.watchtower_alert.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchAlertSeverity {
    Info,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchAlertEvent {
    OlderStateDetected,
    PublicationSubmitted,
    ScanIdle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerAlert {
    pub schema: String,
    pub created_unix_ms: u64,
    pub channel_id: String,
    pub severity: WatchAlertSeverity,
    pub event: WatchAlertEvent,
    pub message: String,
    pub selected_state_number: u64,
    pub observed_state_number: Option<u64>,
    pub observed_out_point: Option<String>,
    pub publication_tx_hash: Option<String>,
    pub scanned_to_block: u64,
    pub next_from_block: u64,
}

impl WatchtowerAlert {
    pub fn new(
        channel_id: String,
        severity: WatchAlertSeverity,
        event: WatchAlertEvent,
        message: String,
        selected_state_number: u64,
        scanned_to_block: u64,
        next_from_block: u64,
    ) -> Result<Self> {
        Ok(Self {
            schema: WATCH_ALERT_SCHEMA.to_string(),
            created_unix_ms: now_unix_ms()?,
            channel_id,
            severity,
            event,
            message,
            selected_state_number,
            observed_state_number: None,
            observed_out_point: None,
            publication_tx_hash: None,
            scanned_to_block,
            next_from_block,
        })
    }

    pub fn with_observed(mut self, state_number: u64, out_point: String) -> Self {
        self.observed_state_number = Some(state_number);
        self.observed_out_point = Some(out_point);
        self
    }

    pub fn with_publication(mut self, tx_hash: String) -> Self {
        self.publication_tx_hash = Some(tx_hash);
        self
    }
}

pub fn append_watchtower_alert(path: &Path, alert: &WatchtowerAlert) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create alert directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open watchtower alert file {}", path.display()))?;
    serde_json::to_writer(&mut file, alert)
        .with_context(|| format!("failed to encode watchtower alert {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to write watchtower alert {}", path.display()))?;
    Ok(())
}

pub fn post_watchtower_alert_webhook(url: &str, alert: &WatchtowerAlert) -> Result<()> {
    ensure!(!url.trim().is_empty(), "watchtower webhook URL is empty");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build watchtower webhook HTTP client")?;
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .json(alert)
        .send()
        .with_context(|| format!("failed to POST watchtower alert webhook {url}"))?;
    let status = response.status();
    ensure!(
        status.is_success(),
        "watchtower alert webhook {url} returned HTTP {status}"
    );
    Ok(())
}

fn now_unix_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?;
    Ok(duration.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_jsonl_alerts() {
        let path =
            std::env::temp_dir().join(format!("morph-watch-alert-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);

        let alert = WatchtowerAlert::new(
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::OlderStateDetected,
            "older state detected".to_string(),
            2,
            10,
            11,
        )
        .unwrap()
        .with_observed(1, "0xabc:0".to_string());

        append_watchtower_alert(&path, &alert).unwrap();
        append_watchtower_alert(&path, &alert).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        let decoded: WatchtowerAlert = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(decoded.event, WatchAlertEvent::OlderStateDetected);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn appends_alert_without_parent_directory() {
        let path = std::path::PathBuf::from(format!(
            "morph-watch-alert-local-{}.jsonl",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let alert = WatchtowerAlert::new(
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            WatchAlertSeverity::Info,
            WatchAlertEvent::ScanIdle,
            "scan idle".to_string(),
            2,
            10,
            11,
        )
        .unwrap();

        append_watchtower_alert(&path, &alert).unwrap();
        assert!(path.exists());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn posts_alert_to_webhook() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n")
                    && request
                        .windows(b"older_state_detected".len())
                        .any(|window| window == b"older_state_detected")
                {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            String::from_utf8(request).unwrap()
        });

        let alert = WatchtowerAlert::new(
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            WatchAlertSeverity::Warning,
            WatchAlertEvent::OlderStateDetected,
            "older state detected".to_string(),
            2,
            10,
            11,
        )
        .unwrap();

        post_watchtower_alert_webhook(&url, &alert).unwrap();
        let request = handle.join().unwrap();
        assert!(request.starts_with("POST / HTTP/1.1"));
        assert!(request.contains("older_state_detected"));
        assert!(request.contains("morph.watchtower_alert.v1"));
    }
}
