use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeSummary {
    pub directory: String,
    pub manifest: BTreeMap<String, String>,
    pub json_files: usize,
    pub transactions: Vec<TransactionSummary>,
    pub script_failures: Vec<ScriptFailureSummary>,
    pub totals: MetricTotals,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionSummary {
    pub check: String,
    pub path: String,
    pub tx_hash: String,
    pub status: Option<String>,
    pub block_number: Option<u64>,
    pub estimated_cycles: u64,
    pub tx_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptFailureSummary {
    pub check: String,
    pub path: String,
    pub source: Option<String>,
    pub error_code: Option<i64>,
    pub morph_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MetricTotals {
    pub transaction_count: usize,
    pub committed_count: usize,
    pub pending_count: usize,
    pub total_estimated_cycles: u64,
    pub max_estimated_cycles: u64,
    pub total_tx_size_bytes: usize,
    pub max_tx_size_bytes: usize,
}

pub fn summarize_devnet_smoke(dir: &Path) -> Result<DevnetSmokeSummary> {
    ensure_directory(dir)?;
    let manifest = read_manifest(dir)?;
    let mut json_paths = Vec::new();
    collect_json_files(dir, &mut json_paths)?;

    let mut transactions = Vec::new();
    let mut script_failures = Vec::new();
    for path in &json_paths {
        let relative = path
            .strip_prefix(dir)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let check = relative.trim_end_matches(".json").to_string();
        let raw = fs::read(path)
            .with_context(|| format!("failed to read smoke JSON {}", path.display()))?;
        let value: Value = serde_json::from_slice(&raw)
            .with_context(|| format!("failed to parse smoke JSON {}", path.display()))?;
        collect_from_value(&check, "$", &value, &mut transactions, &mut script_failures);
    }

    let totals = summarise_totals(&transactions);
    Ok(DevnetSmokeSummary {
        directory: dir.display().to_string(),
        manifest,
        json_files: json_paths.len(),
        transactions,
        script_failures,
        totals,
    })
}

pub fn render_markdown(summary: &DevnetSmokeSummary) -> String {
    let mut out = String::new();
    out.push_str("# Devnet Smoke Summary\n\n");
    out.push_str(&format!("Directory: `{}`\n\n", summary.directory));

    if !summary.manifest.is_empty() {
        out.push_str("## Manifest\n\n");
        out.push_str("| Key | Value |\n");
        out.push_str("| --- | --- |\n");
        for (key, value) in &summary.manifest {
            out.push_str(&format!(
                "| {} | {} |\n",
                table_cell(key),
                table_cell(value)
            ));
        }
        out.push('\n');
    }

    out.push_str("## Totals\n\n");
    out.push_str("| JSON files | Transactions | Committed | Pending | Total cycles | Max cycles | Total bytes | Max bytes |\n");
    out.push_str("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} |\n\n",
        summary.json_files,
        summary.totals.transaction_count,
        summary.totals.committed_count,
        summary.totals.pending_count,
        summary.totals.total_estimated_cycles,
        summary.totals.max_estimated_cycles,
        summary.totals.total_tx_size_bytes,
        summary.totals.max_tx_size_bytes
    ));

    out.push_str("## Transactions\n\n");
    out.push_str("| Check | Path | Status | Block | Cycles | Bytes | Tx |\n");
    out.push_str("| --- | --- | --- | ---: | ---: | ---: | --- |\n");
    for tx in &summary.transactions {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | `{}` |\n",
            table_cell(&tx.check),
            table_cell(&tx.path),
            table_cell(tx.status.as_deref().unwrap_or("")),
            tx.block_number
                .map(|number| number.to_string())
                .unwrap_or_default(),
            tx.estimated_cycles,
            tx.tx_size_bytes,
            tx.tx_hash
        ));
    }
    out.push('\n');

    out.push_str("## Script Failures\n\n");
    if summary.script_failures.is_empty() {
        out.push_str("No expected script failures were recorded.\n");
    } else {
        out.push_str("| Check | Path | Error | Code | Source |\n");
        out.push_str("| --- | --- | --- | ---: | --- |\n");
        for failure in &summary.script_failures {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                table_cell(&failure.check),
                table_cell(&failure.path),
                table_cell(failure.morph_error.as_deref().unwrap_or("")),
                failure
                    .error_code
                    .map(|code| code.to_string())
                    .unwrap_or_default(),
                table_cell(failure.source.as_deref().unwrap_or(""))
            ));
        }
    }

    out
}

fn ensure_directory(dir: &Path) -> Result<()> {
    let metadata = fs::metadata(dir)
        .with_context(|| format!("failed to read smoke directory {}", dir.display()))?;
    if !metadata.is_dir() {
        return Err(anyhow!("{} is not a directory", dir.display()));
    }
    Ok(())
}

fn read_manifest(dir: &Path) -> Result<BTreeMap<String, String>> {
    let path = dir.join("manifest.txt");
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read manifest {}", path.display()))?;
    let mut manifest = BTreeMap::new();
    for line in raw.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        manifest.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(manifest)
}

fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to list directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to list directory {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_json_files(&path, out)?;
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("summary.json") {
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_from_value(
    check: &str,
    path: &str,
    value: &Value,
    transactions: &mut Vec<TransactionSummary>,
    script_failures: &mut Vec<ScriptFailureSummary>,
) {
    let Value::Object(object) = value else {
        return;
    };

    if let Some(tx) = transaction_from_object(check, path, object) {
        transactions.push(tx);
    }

    if let Some(Value::Object(failure)) = object.get("script_failure") {
        script_failures.push(ScriptFailureSummary {
            check: check.to_string(),
            path: append_path(path, "script_failure"),
            source: string_field(failure, "source"),
            error_code: failure.get("error_code").and_then(Value::as_i64),
            morph_error: string_field(failure, "morph_error"),
        });
    }

    for (key, child) in object {
        collect_from_value(
            check,
            &append_path(path, key),
            child,
            transactions,
            script_failures,
        );
    }
}

fn transaction_from_object(
    check: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<TransactionSummary> {
    let tx_hash = string_field(object, "tx_hash")?;
    let metrics = object.get("metrics")?.as_object()?;
    let estimated_cycles = metrics.get("estimated_cycles")?.as_u64()?;
    let tx_size_bytes = metrics.get("tx_size_bytes")?.as_u64()? as usize;
    Some(TransactionSummary {
        check: check.to_string(),
        path: path.to_string(),
        tx_hash,
        status: string_field(object, "status"),
        block_number: object.get("block_number").and_then(Value::as_u64),
        estimated_cycles,
        tx_size_bytes,
    })
}

fn string_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn summarise_totals(transactions: &[TransactionSummary]) -> MetricTotals {
    let mut totals = MetricTotals {
        transaction_count: transactions.len(),
        ..MetricTotals::default()
    };
    for tx in transactions {
        if tx.status.as_deref() == Some("Committed") {
            totals.committed_count += 1;
        }
        if tx.status.as_deref() == Some("Pending") {
            totals.pending_count += 1;
        }
        totals.total_estimated_cycles = totals
            .total_estimated_cycles
            .saturating_add(tx.estimated_cycles);
        totals.max_estimated_cycles = totals.max_estimated_cycles.max(tx.estimated_cycles);
        totals.total_tx_size_bytes = totals.total_tx_size_bytes.saturating_add(tx.tx_size_bytes);
        totals.max_tx_size_bytes = totals.max_tx_size_bytes.max(tx.tx_size_bytes);
    }
    totals
}

fn append_path(parent: &str, child: &str) -> String {
    if parent == "$" {
        format!("$.{child}")
    } else {
        format!("{parent}.{child}")
    }
}

fn table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn summarises_smoke_metrics_and_script_failures() {
        let dir = temp_report_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("manifest.txt"),
            "rpc_url=http://127.0.0.1:18114\nstatus=passed\n",
        )
        .unwrap();
        fs::write(
            dir.join("open.json"),
            r#"{
              "tx_hash": "0xabc",
              "status": "Committed",
              "block_number": 7,
              "metrics": {
                "estimated_cycles": 11,
                "tx_size_bytes": 22
              }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.join("negative.json"),
            r#"{
              "open": {
                "tx_hash": "0xdef",
                "status": "Committed",
                "block_number": 8,
                "metrics": {
                  "estimated_cycles": 33,
                  "tx_size_bytes": 44
                }
              },
              "script_failure": {
                "source": "Inputs",
                "error_code": 16,
                "morph_error": "StateSinceNotMature"
              }
            }"#,
        )
        .unwrap();

        let summary = summarize_devnet_smoke(&dir).unwrap();
        assert_eq!(summary.manifest.get("status").unwrap(), "passed");
        assert_eq!(summary.json_files, 2);
        assert_eq!(summary.transactions.len(), 2);
        assert_eq!(summary.script_failures.len(), 1);
        assert_eq!(summary.totals.total_estimated_cycles, 44);
        assert_eq!(summary.totals.total_tx_size_bytes, 66);

        let markdown = render_markdown(&summary);
        assert!(markdown.contains("StateSinceNotMature"));
        assert!(markdown.contains("0xabc"));

        fs::remove_dir_all(&dir).ok();
    }

    fn temp_report_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "morph-smoke-report-test-{}-{nanos}",
            std::process::id()
        ))
    }
}
