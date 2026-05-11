use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use serde_json::Value;

use crate::packages::StoredFactoryLocalExitPackage;

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeSummary {
    pub directory: String,
    pub manifest: BTreeMap<String, String>,
    pub json_files: usize,
    pub transactions: Vec<TransactionSummary>,
    pub script_failures: Vec<ScriptFailureSummary>,
    pub factory_local_exits: Vec<FactoryLocalExitEvidenceSummary>,
    pub totals: MetricTotals,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeAssertionReport {
    pub directory: String,
    pub git_commit: Option<String>,
    pub git_dirty: Option<String>,
    pub transaction_count: usize,
    pub committed_count: usize,
    pub expected_script_failures: usize,
    pub factory_local_exits: usize,
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

#[derive(Debug, Clone, Serialize)]
pub struct FactoryLocalExitEvidenceSummary {
    pub check: String,
    pub path: String,
    pub factory_id: String,
    pub update_number: u64,
    pub exit_digest: String,
    pub child_channel_id: String,
    pub child_state_number: u64,
    pub child_phase: String,
    pub descriptor_version: u16,
    pub state_output_index: u32,
    pub vault_output_index: u32,
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

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeComparison {
    pub baseline_directory: String,
    pub candidate_directory: String,
    pub compared_transactions: usize,
    pub missing_from_candidate: Vec<String>,
    pub added_in_candidate: Vec<String>,
    pub total_estimated_cycles_delta: i64,
    pub total_tx_size_bytes_delta: i64,
    pub transaction_deltas: Vec<TransactionMetricDelta>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransactionMetricDelta {
    pub key: String,
    pub baseline_status: Option<String>,
    pub candidate_status: Option<String>,
    pub baseline_estimated_cycles: u64,
    pub candidate_estimated_cycles: u64,
    pub estimated_cycles_delta: i64,
    pub baseline_tx_size_bytes: usize,
    pub candidate_tx_size_bytes: usize,
    pub tx_size_bytes_delta: i64,
}

pub fn summarize_devnet_smoke(dir: &Path) -> Result<DevnetSmokeSummary> {
    ensure_directory(dir)?;
    let manifest = read_manifest(dir)?;
    let mut json_paths = Vec::new();
    collect_json_files(dir, &mut json_paths)?;

    let mut transactions = Vec::new();
    let mut script_failures = Vec::new();
    let mut factory_local_exits = Vec::new();
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
        collect_from_value(
            &check,
            "$",
            &value,
            &mut transactions,
            &mut script_failures,
            &mut factory_local_exits,
        )
        .with_context(|| format!("failed to inspect smoke JSON {}", path.display()))?;
    }

    let totals = summarise_totals(&transactions);
    Ok(DevnetSmokeSummary {
        directory: dir.display().to_string(),
        manifest,
        json_files: json_paths.len(),
        transactions,
        script_failures,
        factory_local_exits,
        totals,
    })
}

pub fn compare_devnet_smoke(
    baseline_dir: &Path,
    candidate_dir: &Path,
) -> Result<DevnetSmokeComparison> {
    let baseline = summarize_devnet_smoke(baseline_dir)?;
    let candidate = summarize_devnet_smoke(candidate_dir)?;
    Ok(compare_summaries(&baseline, &candidate))
}

pub fn assert_default_devnet_smoke(dir: &Path) -> Result<DevnetSmokeAssertionReport> {
    let summary = summarize_devnet_smoke(dir)?;
    assert_devnet_smoke_summary(&summary)?;
    Ok(DevnetSmokeAssertionReport {
        git_commit: summary.manifest.get("git_commit").cloned(),
        git_dirty: summary.manifest.get("git_dirty").cloned(),
        directory: summary.directory,
        transaction_count: summary.totals.transaction_count,
        committed_count: summary.totals.committed_count,
        expected_script_failures: EXPECTED_SCRIPT_FAILURES.len(),
        factory_local_exits: summary.factory_local_exits.len(),
    })
}

pub fn assert_devnet_smoke_summary(summary: &DevnetSmokeSummary) -> Result<()> {
    if summary.manifest.get("status").map(String::as_str) != Some("passed") {
        return Err(anyhow!("smoke manifest status is not passed"));
    }
    if summary.totals.transaction_count == 0 || summary.totals.committed_count == 0 {
        return Err(anyhow!("smoke summary contains no committed transactions"));
    }
    if summary.script_failures.len() != EXPECTED_SCRIPT_FAILURES.len() {
        return Err(anyhow!(
            "unexpected script failure count: got {}, expected {}",
            summary.script_failures.len(),
            EXPECTED_SCRIPT_FAILURES.len()
        ));
    }
    for expected in EXPECTED_SCRIPT_FAILURES {
        let found = summary.script_failures.iter().any(|failure| {
            failure.check == expected.check
                && failure.morph_error.as_deref() == Some(expected.morph_error)
                && failure.error_code == Some(expected.error_code)
        });
        if !found {
            return Err(anyhow!(
                "missing expected script failure: {} {} {}",
                expected.check,
                expected.morph_error,
                expected.error_code
            ));
        }
    }

    if summary.factory_local_exits.len() != EXPECTED_FACTORY_LOCAL_EXITS {
        return Err(anyhow!(
            "unexpected factory local-exit evidence count: got {}, expected {}",
            summary.factory_local_exits.len(),
            EXPECTED_FACTORY_LOCAL_EXITS
        ));
    }
    if summary
        .factory_local_exits
        .iter()
        .any(|exit| exit.child_phase != "active" || exit.child_state_number != 0)
    {
        return Err(anyhow!(
            "factory local-exit evidence must create active child state number 0"
        ));
    }
    let ckb_descriptors = summary
        .factory_local_exits
        .iter()
        .filter(|exit| exit.descriptor_version == 1)
        .count();
    let xudt_descriptors = summary
        .factory_local_exits
        .iter()
        .filter(|exit| exit.descriptor_version == 2)
        .count();
    if ckb_descriptors != EXPECTED_FACTORY_CKB_EXITS
        || xudt_descriptors != EXPECTED_FACTORY_XUDT_EXITS
    {
        return Err(anyhow!(
            "unexpected factory descriptor coverage: got CKB {}, xUDT {}; expected CKB {}, xUDT {}",
            ckb_descriptors,
            xudt_descriptors,
            EXPECTED_FACTORY_CKB_EXITS,
            EXPECTED_FACTORY_XUDT_EXITS
        ));
    }
    Ok(())
}

pub fn compare_summaries(
    baseline: &DevnetSmokeSummary,
    candidate: &DevnetSmokeSummary,
) -> DevnetSmokeComparison {
    let baseline_map = transaction_map(&baseline.transactions);
    let candidate_map = transaction_map(&candidate.transactions);

    let mut transaction_deltas = Vec::new();
    let mut missing_from_candidate = Vec::new();
    for (key, baseline_tx) in &baseline_map {
        let Some(candidate_tx) = candidate_map.get(key) else {
            missing_from_candidate.push(key.clone());
            continue;
        };
        transaction_deltas.push(TransactionMetricDelta {
            key: key.clone(),
            baseline_status: baseline_tx.status.clone(),
            candidate_status: candidate_tx.status.clone(),
            baseline_estimated_cycles: baseline_tx.estimated_cycles,
            candidate_estimated_cycles: candidate_tx.estimated_cycles,
            estimated_cycles_delta: signed_delta_u64(
                baseline_tx.estimated_cycles,
                candidate_tx.estimated_cycles,
            ),
            baseline_tx_size_bytes: baseline_tx.tx_size_bytes,
            candidate_tx_size_bytes: candidate_tx.tx_size_bytes,
            tx_size_bytes_delta: signed_delta_usize(
                baseline_tx.tx_size_bytes,
                candidate_tx.tx_size_bytes,
            ),
        });
    }
    transaction_deltas.sort_by(|left, right| left.key.cmp(&right.key));

    let mut added_in_candidate = Vec::new();
    for key in candidate_map.keys() {
        if !baseline_map.contains_key(key) {
            added_in_candidate.push(key.clone());
        }
    }

    DevnetSmokeComparison {
        baseline_directory: baseline.directory.clone(),
        candidate_directory: candidate.directory.clone(),
        compared_transactions: transaction_deltas.len(),
        missing_from_candidate,
        added_in_candidate,
        total_estimated_cycles_delta: signed_delta_u64(
            baseline.totals.total_estimated_cycles,
            candidate.totals.total_estimated_cycles,
        ),
        total_tx_size_bytes_delta: signed_delta_usize(
            baseline.totals.total_tx_size_bytes,
            candidate.totals.total_tx_size_bytes,
        ),
        transaction_deltas,
    }
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
    out.push('\n');

    out.push_str("## Factory Local Exits\n\n");
    if summary.factory_local_exits.is_empty() {
        out.push_str("No factory local-exit evidence packages were recorded.\n");
    } else {
        out.push_str("| Check | Path | Update | Child state | Phase | Descriptor | State out | Vault out | Exit digest |\n");
        out.push_str("| --- | --- | ---: | ---: | --- | ---: | ---: | ---: | --- |\n");
        for exit in &summary.factory_local_exits {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | `{}` |\n",
                table_cell(&exit.check),
                table_cell(&exit.path),
                exit.update_number,
                exit.child_state_number,
                table_cell(&exit.child_phase),
                exit.descriptor_version,
                exit.state_output_index,
                exit.vault_output_index,
                exit.exit_digest
            ));
        }
    }

    out
}

pub fn render_comparison_markdown(comparison: &DevnetSmokeComparison) -> String {
    let mut out = String::new();
    out.push_str("# Devnet Smoke Comparison\n\n");
    out.push_str(&format!(
        "Baseline: `{}`\n\nCandidate: `{}`\n\n",
        comparison.baseline_directory, comparison.candidate_directory
    ));

    out.push_str("## Totals\n\n");
    out.push_str("| Compared txs | Cycle delta | Byte delta | Missing | Added |\n");
    out.push_str("| ---: | ---: | ---: | ---: | ---: |\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} |\n\n",
        comparison.compared_transactions,
        comparison.total_estimated_cycles_delta,
        comparison.total_tx_size_bytes_delta,
        comparison.missing_from_candidate.len(),
        comparison.added_in_candidate.len()
    ));

    out.push_str("## Transaction Deltas\n\n");
    out.push_str("| Transaction | Status | Cycle delta | Byte delta | Baseline cycles | Candidate cycles | Baseline bytes | Candidate bytes |\n");
    out.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for delta in &comparison.transaction_deltas {
        let status = match (&delta.baseline_status, &delta.candidate_status) {
            (Some(left), Some(right)) if left == right => left.clone(),
            (left, right) => format!(
                "{} -> {}",
                left.as_deref().unwrap_or(""),
                right.as_deref().unwrap_or("")
            ),
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            table_cell(&delta.key),
            table_cell(&status),
            delta.estimated_cycles_delta,
            delta.tx_size_bytes_delta,
            delta.baseline_estimated_cycles,
            delta.candidate_estimated_cycles,
            delta.baseline_tx_size_bytes,
            delta.candidate_tx_size_bytes
        ));
    }
    out.push('\n');

    if !comparison.missing_from_candidate.is_empty() {
        out.push_str("## Missing From Candidate\n\n");
        for key in &comparison.missing_from_candidate {
            out.push_str(&format!("- `{}`\n", key));
        }
        out.push('\n');
    }

    if !comparison.added_in_candidate.is_empty() {
        out.push_str("## Added In Candidate\n\n");
        for key in &comparison.added_in_candidate {
            out.push_str(&format!("- `{}`\n", key));
        }
    }

    out
}

struct ExpectedScriptFailure {
    check: &'static str,
    morph_error: &'static str,
    error_code: i64,
}

const EXPECTED_SCRIPT_FAILURES: &[ExpectedScriptFailure] = &[
    ExpectedScriptFailure {
        check: "factory-xudt-negative/smoke",
        morph_error: "SettlementOutputMismatch",
        error_code: 28,
    },
    ExpectedScriptFailure {
        check: "finalise-since-negative-smoke",
        morph_error: "StateSinceNotMature",
        error_code: 16,
    },
    ExpectedScriptFailure {
        check: "sponsor-budget-negative-smoke",
        morph_error: "SponsorFeeTooHigh",
        error_code: 17,
    },
    ExpectedScriptFailure {
        check: "sponsor-policy-negative-smoke",
        morph_error: "SponsorStateOutOfRange",
        error_code: 29,
    },
    ExpectedScriptFailure {
        check: "xudt-negative-smoke",
        morph_error: "SettlementOutputMismatch",
        error_code: 28,
    },
];
const EXPECTED_FACTORY_LOCAL_EXITS: usize = 6;
const EXPECTED_FACTORY_CKB_EXITS: usize = 2;
const EXPECTED_FACTORY_XUDT_EXITS: usize = 4;

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
        let file_name = path.file_name().and_then(|name| name.to_str());
        if file_name == Some("summary.json") || file_name == Some("summary-check.json") {
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
    factory_local_exits: &mut Vec<FactoryLocalExitEvidenceSummary>,
) -> Result<()> {
    let Value::Object(object) = value else {
        return Ok(());
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

    if object.get("schema").and_then(Value::as_str) == Some("morph.factory_local_exit_package.v1") {
        let package: StoredFactoryLocalExitPackage =
            serde_json::from_value(Value::Object(object.clone())).with_context(|| {
                format!("failed to decode factory local-exit package at {path}")
            })?;
        let summary = package
            .summary()
            .with_context(|| format!("invalid factory local-exit package at {path}"))?;
        factory_local_exits.push(FactoryLocalExitEvidenceSummary {
            check: check.to_string(),
            path: path.to_string(),
            factory_id: summary.factory_id,
            update_number: summary.update_number,
            exit_digest: summary.exit_digest,
            child_channel_id: summary.child_channel_id,
            child_state_number: summary.child_state_number,
            child_phase: summary.child_phase,
            descriptor_version: summary.descriptor_version,
            state_output_index: summary.state_output_index,
            vault_output_index: summary.vault_output_index,
        });
    }

    for (key, child) in object {
        collect_from_value(
            check,
            &append_path(path, key),
            child,
            transactions,
            script_failures,
            factory_local_exits,
        )?;
    }
    Ok(())
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

fn transaction_map(transactions: &[TransactionSummary]) -> BTreeMap<String, &TransactionSummary> {
    transactions
        .iter()
        .map(|tx| (format!("{} {}", tx.check, tx.path), tx))
        .collect()
}

fn signed_delta_u64(baseline: u64, candidate: u64) -> i64 {
    candidate.saturating_sub(baseline) as i64 - baseline.saturating_sub(candidate) as i64
}

fn signed_delta_usize(baseline: usize, candidate: usize) -> i64 {
    candidate.saturating_sub(baseline) as i64 - baseline.saturating_sub(candidate) as i64
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
        let local_exit_package =
            serde_json::to_string(&crate::packages::fixture_factory_local_exit_package().unwrap())
                .unwrap();
        fs::write(
            dir.join("factory.json"),
            format!(r#"{{"exit": {{"local_exit_package": {local_exit_package}}}}}"#),
        )
        .unwrap();

        let summary = summarize_devnet_smoke(&dir).unwrap();
        assert_eq!(summary.manifest.get("status").unwrap(), "passed");
        assert_eq!(summary.json_files, 3);
        assert_eq!(summary.transactions.len(), 2);
        assert_eq!(summary.script_failures.len(), 1);
        assert_eq!(summary.factory_local_exits.len(), 1);
        assert_eq!(
            summary.factory_local_exits[0].path,
            "$.exit.local_exit_package"
        );
        assert_eq!(summary.totals.total_estimated_cycles, 44);
        assert_eq!(summary.totals.total_tx_size_bytes, 66);

        let markdown = render_markdown(&summary);
        assert!(markdown.contains("StateSinceNotMature"));
        assert!(markdown.contains("0xabc"));
        assert!(markdown.contains("Factory Local Exits"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn asserts_full_smoke_semantic_coverage() {
        let summary = passing_assertion_summary();
        assert_devnet_smoke_summary(&summary).unwrap();
    }

    #[test]
    fn rejects_missing_expected_smoke_failure() {
        let mut summary = passing_assertion_summary();
        summary.script_failures.pop();
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(err.to_string().contains("unexpected script failure count"));
    }

    #[test]
    fn rejects_incomplete_factory_exit_coverage() {
        let mut summary = passing_assertion_summary();
        summary.factory_local_exits[0].descriptor_version = 2;
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("unexpected factory descriptor coverage")
        );
    }

    #[test]
    fn compares_smoke_summary_metrics() {
        let baseline_dir = temp_report_dir();
        let candidate_dir = temp_report_dir();
        fs::create_dir_all(&baseline_dir).unwrap();
        fs::create_dir_all(&candidate_dir).unwrap();
        write_metric_json(&baseline_dir, "open.json", "0xaaa", 10, 20);
        write_metric_json(&candidate_dir, "open.json", "0xbbb", 13, 18);
        write_metric_json(&candidate_dir, "extra.json", "0xccc", 1, 2);

        let comparison = compare_devnet_smoke(&baseline_dir, &candidate_dir).unwrap();
        assert_eq!(comparison.compared_transactions, 1);
        assert_eq!(comparison.total_estimated_cycles_delta, 4);
        assert_eq!(comparison.total_tx_size_bytes_delta, 0);
        assert_eq!(comparison.added_in_candidate, vec!["extra $".to_string()]);
        assert!(comparison.missing_from_candidate.is_empty());
        assert_eq!(comparison.transaction_deltas[0].estimated_cycles_delta, 3);
        assert_eq!(comparison.transaction_deltas[0].tx_size_bytes_delta, -2);
        assert!(render_comparison_markdown(&comparison).contains("Devnet Smoke Comparison"));

        fs::remove_dir_all(&baseline_dir).ok();
        fs::remove_dir_all(&candidate_dir).ok();
    }

    fn passing_assertion_summary() -> DevnetSmokeSummary {
        let mut manifest = BTreeMap::new();
        manifest.insert("status".to_string(), "passed".to_string());
        DevnetSmokeSummary {
            directory: "target/devnet-smoke/test".to_string(),
            manifest,
            json_files: 36,
            transactions: Vec::new(),
            script_failures: vec![
                failure(
                    "factory-xudt-negative/smoke",
                    "SettlementOutputMismatch",
                    28,
                ),
                failure("finalise-since-negative-smoke", "StateSinceNotMature", 16),
                failure("sponsor-budget-negative-smoke", "SponsorFeeTooHigh", 17),
                failure(
                    "sponsor-policy-negative-smoke",
                    "SponsorStateOutOfRange",
                    29,
                ),
                failure("xudt-negative-smoke", "SettlementOutputMismatch", 28),
            ],
            factory_local_exits: vec![
                factory_exit("factory/exit-channel", 1),
                factory_exit("factory/local-exit-package", 1),
                factory_exit("factory-xudt/local-exit-package", 2),
                factory_exit("factory-xudt/smoke", 2),
                factory_exit("factory-xudt-negative/local-exit-package", 2),
                factory_exit("factory-xudt-negative/smoke", 2),
            ],
            totals: MetricTotals {
                transaction_count: 46,
                committed_count: 45,
                pending_count: 1,
                total_estimated_cycles: 1,
                max_estimated_cycles: 1,
                total_tx_size_bytes: 1,
                max_tx_size_bytes: 1,
            },
        }
    }

    fn failure(check: &str, morph_error: &str, error_code: i64) -> ScriptFailureSummary {
        ScriptFailureSummary {
            check: check.to_string(),
            path: "$.script_failure".to_string(),
            source: Some("Inputs[0].Type".to_string()),
            error_code: Some(error_code),
            morph_error: Some(morph_error.to_string()),
        }
    }

    fn factory_exit(check: &str, descriptor_version: u16) -> FactoryLocalExitEvidenceSummary {
        FactoryLocalExitEvidenceSummary {
            check: check.to_string(),
            path: "$.local_exit_package".to_string(),
            factory_id: "0x00".to_string(),
            update_number: 1,
            exit_digest: "0x11".to_string(),
            child_channel_id: "0x22".to_string(),
            child_state_number: 0,
            child_phase: "active".to_string(),
            descriptor_version,
            state_output_index: 0,
            vault_output_index: 1,
        }
    }

    fn write_metric_json(dir: &Path, file_name: &str, tx_hash: &str, cycles: u64, bytes: usize) {
        fs::write(
            dir.join(file_name),
            format!(
                r#"{{
                  "tx_hash": "{tx_hash}",
                  "status": "Committed",
                  "block_number": 1,
                  "metrics": {{
                    "estimated_cycles": {cycles},
                    "tx_size_bytes": {bytes}
                  }}
                }}"#
            ),
        )
        .unwrap();
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
