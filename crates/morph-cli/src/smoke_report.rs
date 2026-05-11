use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ckb_hash::blake2b_256;
use serde::Serialize;
use serde_json::Value;

use crate::packages::StoredFactoryLocalExitPackage;
use crate::watch_alert::{WatchAlertEvent, WatchAlertSeverity, WatchtowerAlert};

#[derive(Debug, Clone, Serialize)]
pub struct DevnetSmokeSummary {
    pub directory: String,
    pub manifest: BTreeMap<String, String>,
    pub json_files: usize,
    pub transactions: Vec<TransactionSummary>,
    pub script_failures: Vec<ScriptFailureSummary>,
    pub deployed_scripts: Vec<DeployedScriptSummary>,
    pub watchtower_alerts: Vec<WatchtowerAlertSummary>,
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
    pub deployed_scripts: usize,
    pub deployed_script_hashes_verified: bool,
    pub watchtower_alerts: usize,
    pub watchtower_publication_alerts: usize,
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
pub struct DeployedScriptSummary {
    pub check: String,
    pub path: String,
    pub name: String,
    pub out_point: String,
    pub data_hash: String,
    pub hash_type: String,
    pub data_len: usize,
    pub capacity: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchtowerAlertSummary {
    pub check: String,
    pub path: String,
    pub channel_id: String,
    pub severity: String,
    pub event: String,
    pub selected_state_number: u64,
    pub observed_state_number: Option<u64>,
    pub observed_out_point: Option<String>,
    pub publication_tx_hash: Option<String>,
    pub scanned_to_block: u64,
    pub next_from_block: u64,
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
    let mut watch_alert_paths = Vec::new();
    collect_watch_alert_files(dir, &mut watch_alert_paths)?;

    let mut transactions = Vec::new();
    let mut script_failures = Vec::new();
    let mut deployed_scripts = Vec::new();
    let mut watchtower_alerts = Vec::new();
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
            &mut deployed_scripts,
            &mut factory_local_exits,
        )
        .with_context(|| format!("failed to inspect smoke JSON {}", path.display()))?;
    }
    for path in &watch_alert_paths {
        collect_watchtower_alerts(dir, path, &mut watchtower_alerts)?;
    }

    let totals = summarise_totals(&transactions);
    Ok(DevnetSmokeSummary {
        directory: dir.display().to_string(),
        manifest,
        json_files: json_paths.len(),
        transactions,
        script_failures,
        deployed_scripts,
        watchtower_alerts,
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

pub fn assert_default_devnet_smoke(
    dir: &Path,
    contracts_dir: Option<&Path>,
) -> Result<DevnetSmokeAssertionReport> {
    let summary = summarize_devnet_smoke(dir)?;
    assert_devnet_smoke_summary(&summary)?;
    if let Some(contracts_dir) = contracts_dir {
        assert_deployed_script_hashes(&summary, contracts_dir)?;
    }
    Ok(DevnetSmokeAssertionReport {
        git_commit: summary.manifest.get("git_commit").cloned(),
        git_dirty: summary.manifest.get("git_dirty").cloned(),
        directory: summary.directory,
        transaction_count: summary.totals.transaction_count,
        committed_count: summary.totals.committed_count,
        expected_script_failures: EXPECTED_SCRIPT_FAILURES.len(),
        deployed_scripts: summary.deployed_scripts.len(),
        deployed_script_hashes_verified: contracts_dir.is_some(),
        watchtower_alerts: summary.watchtower_alerts.len(),
        watchtower_publication_alerts: summary
            .watchtower_alerts
            .iter()
            .filter(|alert| alert.event == "publication_submitted")
            .count(),
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

    if summary.deployed_scripts.len() != EXPECTED_DEPLOYED_SCRIPT_NAMES.len() {
        return Err(anyhow!(
            "unexpected deployed script count: got {}, expected {}",
            summary.deployed_scripts.len(),
            EXPECTED_DEPLOYED_SCRIPT_NAMES.len()
        ));
    }
    let deployed_names = summary
        .deployed_scripts
        .iter()
        .map(|script| script.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_names = EXPECTED_DEPLOYED_SCRIPT_NAMES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if deployed_names != expected_names {
        return Err(anyhow!(
            "unexpected deployed script set: got {:?}, expected {:?}",
            deployed_names,
            expected_names
        ));
    }
    if summary
        .deployed_scripts
        .iter()
        .any(|script| script.hash_type != "data1" || script.data_len == 0 || script.capacity == 0)
    {
        return Err(anyhow!(
            "deployed scripts must use data1 hashes and non-empty occupied cells"
        ));
    }

    assert_watchtower_alert_coverage(summary)?;

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

fn assert_watchtower_alert_coverage(summary: &DevnetSmokeSummary) -> Result<()> {
    if summary.watchtower_alerts.len() != EXPECTED_WATCHTOWER_ALERTS {
        return Err(anyhow!(
            "unexpected watchtower alert count: got {}, expected {}",
            summary.watchtower_alerts.len(),
            EXPECTED_WATCHTOWER_ALERTS
        ));
    }
    for expected in EXPECTED_WATCHTOWER_EVENTS {
        if !summary
            .watchtower_alerts
            .iter()
            .any(|alert| alert.event == *expected)
        {
            return Err(anyhow!(
                "missing expected watchtower alert event: {expected}"
            ));
        }
    }
    for alert in &summary.watchtower_alerts {
        if alert.severity != "warning" {
            return Err(anyhow!(
                "watchtower alert {} must be warning severity",
                alert.event
            ));
        }
        if alert.next_from_block <= alert.scanned_to_block {
            return Err(anyhow!(
                "watchtower alert {} did not advance the scan cursor",
                alert.event
            ));
        }
        let Some(observed_state_number) = alert.observed_state_number else {
            return Err(anyhow!(
                "watchtower alert {} must include observed state number",
                alert.event
            ));
        };
        if alert.observed_out_point.is_none() {
            return Err(anyhow!(
                "watchtower alert {} must include observed out point",
                alert.event
            ));
        }
        if alert.selected_state_number <= observed_state_number {
            return Err(anyhow!(
                "watchtower alert {} did not select a newer state",
                alert.event
            ));
        }
        if alert.event == "publication_submitted" && alert.publication_tx_hash.is_none() {
            return Err(anyhow!(
                "watchtower publication alert must include publication transaction hash"
            ));
        }
    }
    Ok(())
}

pub fn assert_deployed_script_hashes(
    summary: &DevnetSmokeSummary,
    contracts_dir: &Path,
) -> Result<()> {
    for expected in EXPECTED_DEPLOYED_SCRIPT_NAMES {
        let script = summary
            .deployed_scripts
            .iter()
            .find(|script| script.name == *expected)
            .ok_or_else(|| anyhow!("missing deployed script record for {expected}"))?;
        let path = contracts_dir.join(expected);
        let data = fs::read(&path)
            .with_context(|| format!("failed to read contract binary {}", path.display()))?;
        let expected_hash = format!("0x{}", hex::encode(blake2b_256(&data)));
        if script.data_hash != expected_hash {
            return Err(anyhow!(
                "deployed script {} hash mismatch: summary {}, local {}",
                expected,
                script.data_hash,
                expected_hash
            ));
        }
        if script.data_len != data.len() {
            return Err(anyhow!(
                "deployed script {} length mismatch: summary {}, local {}",
                expected,
                script.data_len,
                data.len()
            ));
        }
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

    out.push_str("## Deployed Scripts\n\n");
    if summary.deployed_scripts.is_empty() {
        out.push_str("No deployed script records were found.\n");
    } else {
        out.push_str("| Name | Out point | Hash type | Data bytes | Capacity | Data hash |\n");
        out.push_str("| --- | --- | --- | ---: | ---: | --- |\n");
        for script in &summary.deployed_scripts {
            out.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | `{}` |\n",
                table_cell(&script.name),
                script.out_point,
                table_cell(&script.hash_type),
                script.data_len,
                script.capacity,
                script.data_hash
            ));
        }
    }
    out.push('\n');

    out.push_str("## Watchtower Alerts\n\n");
    if summary.watchtower_alerts.is_empty() {
        out.push_str("No watchtower alerts were recorded.\n");
    } else {
        out.push_str(
            "| Check | Event | Severity | Selected | Observed | Publication tx | Cursor |\n",
        );
        out.push_str("| --- | --- | --- | ---: | ---: | --- | --- |\n");
        for alert in &summary.watchtower_alerts {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} -> {} |\n",
                table_cell(&alert.check),
                table_cell(&alert.event),
                table_cell(&alert.severity),
                alert.selected_state_number,
                alert
                    .observed_state_number
                    .map(|number| number.to_string())
                    .unwrap_or_default(),
                alert
                    .publication_tx_hash
                    .as_deref()
                    .map(|hash| format!("`{hash}`"))
                    .unwrap_or_default(),
                alert.scanned_to_block,
                alert.next_from_block
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
const EXPECTED_DEPLOYED_SCRIPT_NAMES: &[&str] = &[
    "morph-state-lock",
    "morph-state-type",
    "morph-factory-type",
    "morph-factory-vault-lock",
    "morph-vault-lock",
    "morph-sponsor-lock",
    "morph-devnet-xudt",
];
const EXPECTED_FACTORY_LOCAL_EXITS: usize = 6;
const EXPECTED_FACTORY_CKB_EXITS: usize = 2;
const EXPECTED_FACTORY_XUDT_EXITS: usize = 4;
const EXPECTED_WATCHTOWER_ALERTS: usize = 2;
const EXPECTED_WATCHTOWER_EVENTS: &[&str] = &["older_state_detected", "publication_submitted"];

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

fn collect_watch_alert_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("failed to list directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to list directory {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_watch_alert_files(&path, out)?;
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_watchtower_alerts(
    smoke_dir: &Path,
    path: &Path,
    watchtower_alerts: &mut Vec<WatchtowerAlertSummary>,
) -> Result<()> {
    let relative = path
        .strip_prefix(smoke_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let check = relative.trim_end_matches(".jsonl").to_string();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read watchtower alerts {}", path.display()))?;
    for (line_index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).with_context(|| {
            format!(
                "failed to parse watchtower alert JSONL {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        if value.get("schema").and_then(Value::as_str) != Some("morph.watchtower_alert.v1") {
            continue;
        }
        let alert: WatchtowerAlert = serde_json::from_value(value).with_context(|| {
            format!(
                "failed to decode watchtower alert {} line {}",
                path.display(),
                line_index + 1
            )
        })?;
        watchtower_alerts.push(WatchtowerAlertSummary {
            check: check.clone(),
            path: format!("line {}", line_index + 1),
            channel_id: alert.channel_id,
            severity: watch_alert_severity_name(&alert.severity).to_string(),
            event: watch_alert_event_name(&alert.event).to_string(),
            selected_state_number: alert.selected_state_number,
            observed_state_number: alert.observed_state_number,
            observed_out_point: alert.observed_out_point,
            publication_tx_hash: alert.publication_tx_hash,
            scanned_to_block: alert.scanned_to_block,
            next_from_block: alert.next_from_block,
        });
    }
    Ok(())
}

fn watch_alert_severity_name(severity: &WatchAlertSeverity) -> &'static str {
    match severity {
        WatchAlertSeverity::Info => "info",
        WatchAlertSeverity::Warning => "warning",
    }
}

fn watch_alert_event_name(event: &WatchAlertEvent) -> &'static str {
    match event {
        WatchAlertEvent::OlderStateDetected => "older_state_detected",
        WatchAlertEvent::PublicationSubmitted => "publication_submitted",
        WatchAlertEvent::ScanIdle => "scan_idle",
    }
}

fn collect_from_value(
    check: &str,
    path: &str,
    value: &Value,
    transactions: &mut Vec<TransactionSummary>,
    script_failures: &mut Vec<ScriptFailureSummary>,
    deployed_scripts: &mut Vec<DeployedScriptSummary>,
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

    if let Some(Value::Array(scripts)) = object.get("scripts") {
        for (index, script) in scripts.iter().enumerate() {
            let Value::Object(script) = script else {
                continue;
            };
            if let Some(deployed_script) = deployed_script_from_object(
                check,
                &append_index_path(path, "scripts", index),
                script,
            ) {
                deployed_scripts.push(deployed_script);
            }
        }
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
            deployed_scripts,
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

fn deployed_script_from_object(
    check: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
) -> Option<DeployedScriptSummary> {
    let name = string_field(object, "name")?;
    let data_hash = string_field(object, "data_hash")?;
    let hash_type = string_field(object, "hash_type")?;
    let data_len = object.get("data_len")?.as_u64()? as usize;
    let capacity = object.get("capacity")?.as_u64()?;
    let out_point = object.get("out_point")?.as_object()?;
    let tx_hash = string_field(out_point, "tx_hash")?;
    let index = out_point.get("index")?.as_u64()?;
    Some(DeployedScriptSummary {
        check: check.to_string(),
        path: path.to_string(),
        name,
        out_point: format!("{tx_hash}:{index}"),
        data_hash,
        hash_type,
        data_len,
        capacity,
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

fn append_index_path(parent: &str, child: &str, index: usize) -> String {
    if parent == "$" {
        format!("$.{child}[{index}]")
    } else {
        format!("{parent}.{child}[{index}]")
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
        fs::write(
            dir.join("deploy.json"),
            r#"{
              "scripts": [{
                "name": "morph-state-lock",
                "out_point": {
                  "tx_hash": "0xabc",
                  "index": 0
                },
                "data_hash": "0x123",
                "hash_type": "data1",
                "data_len": 11,
                "capacity": 22
              }]
            }"#,
        )
        .unwrap();
        fs::write(
            dir.join("watch-alerts.jsonl"),
            concat!(
                r#"{"schema":"morph.watchtower_alert.v1","created_unix_ms":1,"channel_id":"0x1111111111111111111111111111111111111111111111111111111111111111","severity":"warning","event":"older_state_detected","message":"old state","selected_state_number":2,"observed_state_number":0,"observed_out_point":"0xabc:0","publication_tx_hash":null,"scanned_to_block":10,"next_from_block":11}"#,
                "\n",
                r#"{"schema":"morph.watchtower_alert.v1","created_unix_ms":2,"channel_id":"0x1111111111111111111111111111111111111111111111111111111111111111","severity":"warning","event":"publication_submitted","message":"published","selected_state_number":2,"observed_state_number":0,"observed_out_point":"0xabc:0","publication_tx_hash":"0xdef","scanned_to_block":10,"next_from_block":11}"#,
                "\n",
            ),
        )
        .unwrap();

        let summary = summarize_devnet_smoke(&dir).unwrap();
        assert_eq!(summary.manifest.get("status").unwrap(), "passed");
        assert_eq!(summary.json_files, 4);
        assert_eq!(summary.transactions.len(), 2);
        assert_eq!(summary.script_failures.len(), 1);
        assert_eq!(summary.deployed_scripts.len(), 1);
        assert_eq!(summary.deployed_scripts[0].name, "morph-state-lock");
        assert_eq!(summary.factory_local_exits.len(), 1);
        assert_eq!(
            summary.factory_local_exits[0].path,
            "$.exit.local_exit_package"
        );
        assert_eq!(summary.watchtower_alerts.len(), 2);
        assert_eq!(summary.watchtower_alerts[1].event, "publication_submitted");
        assert_eq!(summary.totals.total_estimated_cycles, 44);
        assert_eq!(summary.totals.total_tx_size_bytes, 66);

        let markdown = render_markdown(&summary);
        assert!(markdown.contains("StateSinceNotMature"));
        assert!(markdown.contains("0xabc"));
        assert!(markdown.contains("Deployed Scripts"));
        assert!(markdown.contains("Watchtower Alerts"));
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
    fn rejects_incomplete_deployment_coverage() {
        let mut summary = passing_assertion_summary();
        summary.deployed_scripts.pop();
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(err.to_string().contains("unexpected deployed script count"));
    }

    #[test]
    fn rejects_missing_watchtower_alert_coverage() {
        let mut summary = passing_assertion_summary();
        summary
            .watchtower_alerts
            .retain(|alert| alert.event != "publication_submitted");
        let err = assert_devnet_smoke_summary(&summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("unexpected watchtower alert count")
        );
    }

    #[test]
    fn verifies_deployed_script_hashes_against_local_binaries() {
        let dir = temp_report_dir();
        fs::create_dir_all(&dir).unwrap();
        let mut summary = passing_assertion_summary();
        for (index, script) in summary.deployed_scripts.iter_mut().enumerate() {
            let data = vec![index as u8; index + 1];
            fs::write(dir.join(&script.name), &data).unwrap();
            script.data_hash = format!("0x{}", hex::encode(blake2b_256(&data)));
            script.data_len = data.len();
        }

        assert_deployed_script_hashes(&summary, &dir).unwrap();
        summary.deployed_scripts[0].data_hash = "0x00".to_string();
        let err = assert_deployed_script_hashes(&summary, &dir).unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));

        fs::remove_dir_all(&dir).ok();
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
            watchtower_alerts: watchtower_alerts(),
            factory_local_exits: vec![
                factory_exit("factory/exit-channel", 1),
                factory_exit("factory/local-exit-package", 1),
                factory_exit("factory-xudt/local-exit-package", 2),
                factory_exit("factory-xudt/smoke", 2),
                factory_exit("factory-xudt-negative/local-exit-package", 2),
                factory_exit("factory-xudt-negative/smoke", 2),
            ],
            deployed_scripts: deployed_scripts(),
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

    fn deployed_scripts() -> Vec<DeployedScriptSummary> {
        EXPECTED_DEPLOYED_SCRIPT_NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| DeployedScriptSummary {
                check: "deploy-contracts".to_string(),
                path: format!("$.scripts[{index}]"),
                name: (*name).to_string(),
                out_point: format!("0x{index}:0"),
                data_hash: format!("0x{index}"),
                hash_type: "data1".to_string(),
                data_len: 1,
                capacity: 1,
            })
            .collect()
    }

    fn watchtower_alerts() -> Vec<WatchtowerAlertSummary> {
        vec![
            WatchtowerAlertSummary {
                check: "watch-auto-sponsor/watch-alerts".to_string(),
                path: "line 1".to_string(),
                channel_id: "0x11".to_string(),
                severity: "warning".to_string(),
                event: "older_state_detected".to_string(),
                selected_state_number: 2,
                observed_state_number: Some(0),
                observed_out_point: Some("0xabc:0".to_string()),
                publication_tx_hash: None,
                scanned_to_block: 10,
                next_from_block: 11,
            },
            WatchtowerAlertSummary {
                check: "watch-auto-sponsor/watch-alerts".to_string(),
                path: "line 2".to_string(),
                channel_id: "0x11".to_string(),
                severity: "warning".to_string(),
                event: "publication_submitted".to_string(),
                selected_state_number: 2,
                observed_state_number: Some(0),
                observed_out_point: Some("0xabc:0".to_string()),
                publication_tx_hash: Some("0xdef".to_string()),
                scanned_to_block: 10,
                next_from_block: 11,
            },
        ]
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
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "morph-smoke-report-test-{}-{nanos}-{counter}",
            std::process::id()
        ))
    }
}
