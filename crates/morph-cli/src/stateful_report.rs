use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};

use crate::smoke_report::{
    self, DevnetSmokeAssertionReport, DevnetSmokeBudgetLimits, DevnetSmokeProofProfileBudgetLimit,
    DevnetSmokeSummary, DevnetSmokeTransactionBudgetLimit,
};

const DEVNET_STATEFUL_BUDGET_SCHEMA: &str = "morph.devnet_stateful_budget.v1";
const DEVNET_STATEFUL_SCENARIO_SCHEMA: &str = "morph.devnet_stateful_scenario.v1";
const DEVNET_AUDIT_PROFILE_SCHEMA: &str = "morph.devnet_audit_profile.v1";

const REQUIRED_SCENARIOS: &[&str] = &[
    "bilateral_supersede_watchtower_finalise",
    "bilateral_direct_publish_finalise",
    "sponsor_fee_pressure",
    "splice_lifecycle_matrix",
    "factory_lifecycle_matrix",
    "factory_splice_then_exit",
    "watchtower_operations",
    "extreme_state_value_cases",
    "negative_attack_matrix",
];

#[derive(Debug, Clone, Serialize)]
pub struct DevnetStatefulSummary {
    pub directory: String,
    pub manifest: BTreeMap<String, String>,
    pub scenarios: Vec<StatefulScenarioSummary>,
    pub audit_families: Vec<AuditFamilySummary>,
    pub unknown_coverage_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoke: Option<DevnetSmokeSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatefulScenarioSummary {
    pub scenario_id: String,
    pub category: String,
    pub description: String,
    pub references: Vec<String>,
    pub required_committed_checks: Vec<String>,
    pub expected_failures: Vec<StatefulExpectedFailure>,
    pub coverage: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetStatefulAssertionReport {
    pub directory: String,
    pub git_commit: Option<String>,
    pub git_dirty: Option<String>,
    pub scenario_count: usize,
    pub required_scenarios: usize,
    pub audit_families: usize,
    pub audit_families_passed: usize,
    pub unknown_coverage_tags: Vec<String>,
    pub referenced_artifacts: usize,
    pub required_committed_checks: usize,
    pub expected_failures: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoke: Option<DevnetSmokeAssertionReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DevnetStatefulComparison {
    pub baseline_directory: String,
    pub candidate_directory: String,
    pub missing_scenarios: Vec<String>,
    pub added_scenarios: Vec<String>,
    pub audit_family_deltas: Vec<AuditFamilyStatusDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoke: Option<smoke_report::DevnetSmokeComparison>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFamilySummary {
    pub id: String,
    pub severity: String,
    pub principle: String,
    pub passed: bool,
    pub missing_tags: Vec<String>,
    pub missing_scenarios: Vec<String>,
    pub missing_checks: Vec<String>,
    pub missing_failures: Vec<StatefulExpectedFailure>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFamilyStatusDelta {
    pub id: String,
    pub baseline_passed: Option<bool>,
    pub candidate_passed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct StatefulScenarioFile {
    schema: String,
    scenario_id: String,
    category: String,
    description: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    required_committed_checks: Vec<String>,
    #[serde(default)]
    expected_failures: Vec<StatefulExpectedFailure>,
    #[serde(default)]
    coverage: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DevnetAuditProfile {
    schema: String,
    pub families: Vec<AuditFamilyProfile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditFamilyProfile {
    pub id: String,
    pub severity: String,
    pub principle: String,
    #[serde(default)]
    pub required_coverage_tags: Vec<String>,
    #[serde(default)]
    pub required_scenarios: Vec<String>,
    #[serde(default)]
    pub required_committed_checks: Vec<String>,
    #[serde(default)]
    pub required_expected_failures: Vec<StatefulExpectedFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatefulExpectedFailure {
    pub check: String,
    pub morph_error: String,
    pub error_code: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct DevnetStatefulBudgetProfile {
    schema: String,
    max_total_cycles: Option<u64>,
    max_tx_cycles: Option<u64>,
    max_total_bytes: Option<usize>,
    max_tx_bytes: Option<usize>,
    #[serde(default)]
    transactions: Vec<DevnetSmokeTransactionBudgetLimit>,
    #[serde(default)]
    proof_profiles: Vec<DevnetSmokeProofProfileBudgetLimit>,
}

#[derive(Debug, Clone)]
struct AuditFamilyEvaluation {
    families: Vec<AuditFamilySummary>,
    unknown_coverage_tags: Vec<String>,
}

pub fn summarize_devnet_stateful_with_audit(
    dir: &Path,
    audit_profile: Option<&DevnetAuditProfile>,
) -> Result<DevnetStatefulSummary> {
    ensure_directory(dir)?;
    let manifest = read_manifest(dir)?;
    let scenario_files = read_scenario_files(dir)?;
    let scenarios = scenario_files
        .iter()
        .map(|scenario| StatefulScenarioSummary {
            scenario_id: scenario.scenario_id.clone(),
            category: scenario.category.clone(),
            description: scenario.description.clone(),
            references: scenario.references.clone(),
            required_committed_checks: scenario.required_committed_checks.clone(),
            expected_failures: scenario.expected_failures.clone(),
            coverage: scenario.coverage.clone(),
        })
        .collect::<Vec<_>>();
    let smoke_dir = dir.join("smoke");
    let smoke = smoke_dir
        .is_dir()
        .then(|| smoke_report::summarize_devnet_smoke(&smoke_dir))
        .transpose()?;
    let mut summary = DevnetStatefulSummary {
        directory: dir.display().to_string(),
        manifest,
        scenarios,
        audit_families: Vec::new(),
        unknown_coverage_tags: Vec::new(),
        smoke,
    };
    if let Some(profile) = audit_profile {
        let audit = audit_family_summaries(&summary, profile);
        summary.audit_families = audit.families;
        summary.unknown_coverage_tags = audit.unknown_coverage_tags;
    }
    Ok(summary)
}

pub fn read_audit_profile(path: &Path) -> Result<DevnetAuditProfile> {
    let raw = fs::read(path)
        .with_context(|| format!("failed to read devnet audit profile {}", path.display()))?;
    let profile: DevnetAuditProfile = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse devnet audit profile {}", path.display()))?;
    if profile.schema != DEVNET_AUDIT_PROFILE_SCHEMA {
        return Err(anyhow!(
            "unsupported devnet audit profile schema {}",
            profile.schema
        ));
    }
    ensure!(
        !profile.families.is_empty(),
        "devnet audit profile must contain at least one family"
    );
    let mut ids = BTreeSet::new();
    for family in &profile.families {
        ensure!(!family.id.is_empty(), "audit family id must not be empty");
        ensure!(
            ids.insert(family.id.clone()),
            "duplicate audit family id {}",
            family.id
        );
    }
    Ok(profile)
}

pub fn read_stateful_budget_profile(path: &Path) -> Result<DevnetSmokeBudgetLimits> {
    let raw = fs::read(path).with_context(|| {
        format!(
            "failed to read devnet stateful budget profile {}",
            path.display()
        )
    })?;
    let profile: DevnetStatefulBudgetProfile = serde_json::from_slice(&raw).with_context(|| {
        format!(
            "failed to parse devnet stateful budget profile {}",
            path.display()
        )
    })?;
    if profile.schema != DEVNET_STATEFUL_BUDGET_SCHEMA {
        return Err(anyhow!(
            "unsupported devnet stateful budget profile schema {}",
            profile.schema
        ));
    }
    Ok(DevnetSmokeBudgetLimits {
        max_total_cycles: profile.max_total_cycles,
        max_tx_cycles: profile.max_tx_cycles,
        max_total_bytes: profile.max_total_bytes,
        max_tx_bytes: profile.max_tx_bytes,
        transactions: profile.transactions,
        proof_profiles: profile.proof_profiles,
    })
}

pub fn assert_default_devnet_stateful(
    dir: &Path,
    budget_limits: Option<&DevnetSmokeBudgetLimits>,
    audit_profile: Option<&DevnetAuditProfile>,
) -> Result<DevnetStatefulAssertionReport> {
    let summary = summarize_devnet_stateful_with_audit(dir, audit_profile)?;
    assert_stateful_summary(&summary)?;
    assert_audit_families(&summary, audit_profile, budget_limits)?;
    let smoke_report = if let Some(smoke) = &summary.smoke {
        let smoke_dir = dir.join("smoke");
        let report = if budget_limits
            .map(DevnetSmokeBudgetLimits::has_any_limit)
            .unwrap_or(false)
        {
            smoke_report::assert_default_devnet_smoke_with_budget(&smoke_dir, None, budget_limits)?
        } else {
            smoke_report::assert_default_devnet_smoke(&smoke_dir, None)?
        };
        ensure!(
            smoke.totals.transaction_count == report.transaction_count,
            "stateful smoke transaction count changed during assertion"
        );
        Some(report)
    } else {
        None
    };
    let referenced_artifacts = summary
        .scenarios
        .iter()
        .map(|scenario| scenario.references.len())
        .sum();
    let required_committed_checks = summary
        .scenarios
        .iter()
        .map(|scenario| scenario.required_committed_checks.len())
        .sum();
    let expected_failures = summary
        .scenarios
        .iter()
        .map(|scenario| scenario.expected_failures.len())
        .sum();
    Ok(DevnetStatefulAssertionReport {
        directory: summary.directory,
        git_commit: summary.manifest.get("git_commit").cloned(),
        git_dirty: summary.manifest.get("git_dirty").cloned(),
        scenario_count: summary.scenarios.len(),
        required_scenarios: REQUIRED_SCENARIOS.len(),
        audit_families: summary.audit_families.len(),
        audit_families_passed: summary
            .audit_families
            .iter()
            .filter(|family| family.passed)
            .count(),
        unknown_coverage_tags: summary.unknown_coverage_tags.clone(),
        referenced_artifacts,
        required_committed_checks,
        expected_failures,
        smoke: smoke_report,
    })
}

pub fn compare_devnet_stateful_with_audit(
    baseline_dir: &Path,
    candidate_dir: &Path,
    audit_profile: Option<&DevnetAuditProfile>,
) -> Result<DevnetStatefulComparison> {
    let baseline = summarize_devnet_stateful_with_audit(baseline_dir, audit_profile)?;
    let candidate = summarize_devnet_stateful_with_audit(candidate_dir, audit_profile)?;
    let baseline_ids = scenario_id_set(&baseline);
    let candidate_ids = scenario_id_set(&candidate);
    let missing_scenarios = baseline_ids
        .difference(&candidate_ids)
        .cloned()
        .collect::<Vec<_>>();
    let added_scenarios = candidate_ids
        .difference(&baseline_ids)
        .cloned()
        .collect::<Vec<_>>();
    let baseline_smoke = baseline_dir.join("smoke");
    let candidate_smoke = candidate_dir.join("smoke");
    let smoke = if baseline_smoke.is_dir() && candidate_smoke.is_dir() {
        Some(smoke_report::compare_devnet_smoke(
            &baseline_smoke,
            &candidate_smoke,
        )?)
    } else {
        None
    };
    let audit_family_deltas = audit_family_status_deltas(&baseline, &candidate);
    Ok(DevnetStatefulComparison {
        baseline_directory: baseline.directory,
        candidate_directory: candidate.directory,
        missing_scenarios,
        added_scenarios,
        audit_family_deltas,
        smoke,
    })
}

pub fn assert_stateful_comparison_limits(
    comparison: &DevnetStatefulComparison,
    fail_on_status_change: bool,
) -> Result<()> {
    if fail_on_status_change
        && (!comparison.missing_scenarios.is_empty() || !comparison.added_scenarios.is_empty())
    {
        return Err(anyhow!(
            "stateful scenario set changed: missing {:?}, added {:?}",
            comparison.missing_scenarios,
            comparison.added_scenarios
        ));
    }
    if fail_on_status_change && !comparison.audit_family_deltas.is_empty() {
        return Err(anyhow!(
            "stateful audit family status changed: {:?}",
            comparison.audit_family_deltas
        ));
    }
    if fail_on_status_change && let Some(smoke) = &comparison.smoke {
        let limits = smoke_report::DevnetSmokeComparisonLimits {
            fail_on_transaction_set_change: false,
            fail_on_status_change: true,
            max_abs_total_cycle_delta: None,
            max_abs_tx_cycle_delta: None,
            max_abs_total_byte_delta: None,
            max_abs_tx_byte_delta: None,
        };
        smoke_report::assert_comparison_limits(smoke, &limits)?;
    }
    Ok(())
}

pub fn render_markdown(summary: &DevnetStatefulSummary) -> String {
    let mut out = String::new();
    out.push_str("# Devnet Stateful Summary\n\n");
    out.push_str(&format!("Directory: `{}`\n\n", summary.directory));
    if !summary.manifest.is_empty() {
        out.push_str("## Manifest\n\n");
        out.push_str("| Key | Value |\n| --- | --- |\n");
        for (key, value) in &summary.manifest {
            out.push_str(&format!(
                "| {} | {} |\n",
                table_cell(key),
                table_cell(value)
            ));
        }
        out.push('\n');
    }
    out.push_str("## Scenarios\n\n");
    out.push_str("| Scenario | Category | References | Required commits | Expected failures |\n");
    out.push_str("| --- | --- | ---: | ---: | ---: |\n");
    for scenario in &summary.scenarios {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            table_cell(&scenario.scenario_id),
            table_cell(&scenario.category),
            scenario.references.len(),
            scenario.required_committed_checks.len(),
            scenario.expected_failures.len()
        ));
    }
    out.push('\n');
    if !summary.audit_families.is_empty() || !summary.unknown_coverage_tags.is_empty() {
        out.push_str("## Audit Families\n\n");
        if !summary.unknown_coverage_tags.is_empty() {
            out.push_str(&format!(
                "Unknown coverage tags: `{}`\n\n",
                summary.unknown_coverage_tags.join("`, `")
            ));
        }
        out.push_str("| Family | Severity | Status | Missing tags | Missing scenarios | Missing checks | Missing failures |\n");
        out.push_str("| --- | --- | --- | ---: | ---: | ---: | ---: |\n");
        for family in &summary.audit_families {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                table_cell(&family.id),
                table_cell(&family.severity),
                if family.passed { "passed" } else { "missing" },
                family.missing_tags.len(),
                family.missing_scenarios.len(),
                family.missing_checks.len(),
                family.missing_failures.len()
            ));
        }
        out.push('\n');
    }
    if let Some(smoke) = &summary.smoke {
        out.push_str("## Underlying Smoke Totals\n\n");
        out.push_str("| Transactions | Committed | Pending | Script failures | Watchtower alerts | Factory exits | Factory splices |\n");
        out.push_str("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n\n",
            smoke.totals.transaction_count,
            smoke.totals.committed_count,
            smoke.totals.pending_count,
            smoke.script_failures.len(),
            smoke.watchtower_alerts.len(),
            smoke.factory_reduced_exits.len(),
            smoke.factory_splices.len()
        ));
    }
    out
}

pub fn render_comparison_markdown(comparison: &DevnetStatefulComparison) -> String {
    let mut out = String::new();
    out.push_str("# Devnet Stateful Comparison\n\n");
    out.push_str(&format!(
        "Baseline: `{}`\n\nCandidate: `{}`\n\n",
        comparison.baseline_directory, comparison.candidate_directory
    ));
    out.push_str("## Scenario Set\n\n");
    out.push_str(&format!(
        "- Missing from candidate: {}\n",
        comparison.missing_scenarios.len()
    ));
    for scenario in &comparison.missing_scenarios {
        out.push_str(&format!("  - `{scenario}`\n"));
    }
    out.push_str(&format!(
        "- Added in candidate: {}\n",
        comparison.added_scenarios.len()
    ));
    for scenario in &comparison.added_scenarios {
        out.push_str(&format!("  - `{scenario}`\n"));
    }
    if !comparison.audit_family_deltas.is_empty() {
        out.push_str("\n## Audit Family Status\n\n");
        out.push_str("| Family | Baseline | Candidate |\n| --- | --- | --- |\n");
        for delta in &comparison.audit_family_deltas {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                table_cell(&delta.id),
                audit_status_cell(delta.baseline_passed),
                audit_status_cell(delta.candidate_passed)
            ));
        }
    }
    if let Some(smoke) = &comparison.smoke {
        out.push('\n');
        out.push_str(&smoke_report::render_comparison_markdown(smoke));
    }
    out
}

fn assert_stateful_summary(summary: &DevnetStatefulSummary) -> Result<()> {
    ensure!(
        summary.manifest.get("status").map(String::as_str) == Some("passed"),
        "stateful manifest status is not passed"
    );
    let scenario_ids = scenario_id_set(summary);
    for required in REQUIRED_SCENARIOS {
        ensure!(
            scenario_ids.contains(*required),
            "missing required stateful scenario {required}"
        );
    }
    for scenario in &summary.scenarios {
        ensure!(
            !scenario.references.is_empty(),
            "scenario {} has no referenced artifacts",
            scenario.scenario_id
        );
        for reference in &scenario.references {
            ensure!(
                Path::new(reference).is_relative(),
                "scenario {} reference must be relative: {}",
                scenario.scenario_id,
                reference
            );
            ensure!(
                Path::new(reference)
                    .components()
                    .all(|component| { !matches!(component, std::path::Component::ParentDir) }),
                "scenario {} reference must not escape directory: {}",
                scenario.scenario_id,
                reference
            );
            let path = Path::new(&summary.directory).join(reference);
            ensure!(
                path.exists(),
                "scenario {} referenced artifact does not exist: {}",
                scenario.scenario_id,
                reference
            );
        }
    }
    let smoke = summary
        .smoke
        .as_ref()
        .ok_or_else(|| anyhow!("stateful directory is missing underlying smoke summary"))?;
    smoke_report::assert_devnet_smoke_summary(smoke)?;
    for scenario in &summary.scenarios {
        for check in &scenario.required_committed_checks {
            let found = smoke
                .transactions
                .iter()
                .any(|tx| tx.check == *check && tx.status.as_deref() == Some("Committed"));
            ensure!(
                found,
                "scenario {} missing committed transaction check {}",
                scenario.scenario_id,
                check
            );
        }
        for expected in &scenario.expected_failures {
            let found = smoke.script_failures.iter().any(|failure| {
                failure.check == expected.check
                    && failure.morph_error.as_deref() == Some(expected.morph_error.as_str())
                    && failure.error_code == Some(expected.error_code)
            });
            ensure!(
                found,
                "scenario {} missing expected failure {} {} {}",
                scenario.scenario_id,
                expected.check,
                expected.morph_error,
                expected.error_code
            );
        }
    }
    Ok(())
}

fn assert_audit_families(
    summary: &DevnetStatefulSummary,
    audit_profile: Option<&DevnetAuditProfile>,
    budget_limits: Option<&DevnetSmokeBudgetLimits>,
) -> Result<()> {
    if audit_profile.is_none() {
        return Ok(());
    }
    ensure!(
        summary.unknown_coverage_tags.is_empty(),
        "stateful scenarios contain unknown coverage tags: {:?}",
        summary.unknown_coverage_tags
    );
    if summary
        .audit_families
        .iter()
        .any(|family| family.id == "budget_regression")
    {
        ensure!(
            budget_limits
                .map(DevnetSmokeBudgetLimits::has_any_limit)
                .unwrap_or(false),
            "budget_regression requires a stateful budget profile"
        );
    }
    for family in &summary.audit_families {
        ensure!(
            family.passed,
            "audit family {} missing evidence: tags {:?}, scenarios {:?}, checks {:?}, failures {:?}",
            family.id,
            family.missing_tags,
            family.missing_scenarios,
            family.missing_checks,
            family.missing_failures
        );
    }
    Ok(())
}

fn audit_family_summaries(
    summary: &DevnetStatefulSummary,
    profile: &DevnetAuditProfile,
) -> AuditFamilyEvaluation {
    let scenario_ids = scenario_id_set(summary);
    let coverage_tags = coverage_tag_set(summary);
    let known_tags = profile
        .families
        .iter()
        .flat_map(|family| family.required_coverage_tags.iter().cloned())
        .collect::<BTreeSet<_>>();
    let unknown_coverage_tags = coverage_tags
        .difference(&known_tags)
        .cloned()
        .collect::<Vec<_>>();
    let families = profile
        .families
        .iter()
        .map(|family| {
            let missing_tags = missing_strings(&family.required_coverage_tags, &coverage_tags);
            let missing_scenarios = missing_strings(&family.required_scenarios, &scenario_ids);
            let missing_checks = family
                .required_committed_checks
                .iter()
                .filter(|check| !has_committed_check(summary, check))
                .cloned()
                .collect::<Vec<_>>();
            let missing_failures = family
                .required_expected_failures
                .iter()
                .filter(|failure| !has_exact_failure(summary, failure))
                .cloned()
                .collect::<Vec<_>>();
            let passed = missing_tags.is_empty()
                && missing_scenarios.is_empty()
                && missing_checks.is_empty()
                && missing_failures.is_empty();
            AuditFamilySummary {
                id: family.id.clone(),
                severity: family.severity.clone(),
                principle: family.principle.clone(),
                passed,
                missing_tags,
                missing_scenarios,
                missing_checks,
                missing_failures,
            }
        })
        .collect();
    AuditFamilyEvaluation {
        families,
        unknown_coverage_tags,
    }
}

fn audit_family_status_deltas(
    baseline: &DevnetStatefulSummary,
    candidate: &DevnetStatefulSummary,
) -> Vec<AuditFamilyStatusDelta> {
    let baseline_status = audit_family_status_map(baseline);
    let candidate_status = audit_family_status_map(candidate);
    let ids = baseline_status
        .keys()
        .chain(candidate_status.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    ids.into_iter()
        .filter_map(|id| {
            let baseline_passed = baseline_status.get(&id).copied();
            let candidate_passed = candidate_status.get(&id).copied();
            (baseline_passed != candidate_passed).then_some(AuditFamilyStatusDelta {
                id,
                baseline_passed,
                candidate_passed,
            })
        })
        .collect()
}

fn audit_family_status_map(summary: &DevnetStatefulSummary) -> BTreeMap<String, bool> {
    summary
        .audit_families
        .iter()
        .map(|family| (family.id.clone(), family.passed))
        .collect()
}

fn missing_strings(required: &[String], actual: &BTreeSet<String>) -> Vec<String> {
    required
        .iter()
        .filter(|value| !actual.contains(*value))
        .cloned()
        .collect()
}

fn coverage_tag_set(summary: &DevnetStatefulSummary) -> BTreeSet<String> {
    summary
        .scenarios
        .iter()
        .flat_map(|scenario| scenario.coverage.iter().cloned())
        .collect()
}

fn has_committed_check(summary: &DevnetStatefulSummary, check: &str) -> bool {
    summary.smoke.as_ref().is_some_and(|smoke| {
        smoke
            .transactions
            .iter()
            .any(|tx| tx.check == check && tx.status.as_deref() == Some("Committed"))
    })
}

fn has_exact_failure(summary: &DevnetStatefulSummary, expected: &StatefulExpectedFailure) -> bool {
    summary.smoke.as_ref().is_some_and(|smoke| {
        smoke.script_failures.iter().any(|failure| {
            failure.check == expected.check
                && failure.morph_error.as_deref() == Some(expected.morph_error.as_str())
                && failure.error_code == Some(expected.error_code)
        })
    })
}

fn read_scenario_files(dir: &Path) -> Result<Vec<StatefulScenarioFile>> {
    let mut paths = fs::read_dir(dir)
        .with_context(|| format!("failed to list stateful directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to list stateful directory {}", dir.display()))?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter(|path| {
            !matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("summary.json" | "summary-check.json" | "summary-budget-check.json")
            )
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut scenarios = Vec::new();
    for path in paths {
        let raw = fs::read(&path)
            .with_context(|| format!("failed to read stateful scenario {}", path.display()))?;
        let scenario: StatefulScenarioFile = serde_json::from_slice(&raw)
            .with_context(|| format!("failed to parse stateful scenario {}", path.display()))?;
        ensure!(
            scenario.schema == DEVNET_STATEFUL_SCENARIO_SCHEMA,
            "unsupported stateful scenario schema {} in {}",
            scenario.schema,
            path.display()
        );
        scenarios.push(scenario);
    }
    Ok(scenarios)
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
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            manifest.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(manifest)
}

fn ensure_directory(dir: &Path) -> Result<()> {
    ensure!(dir.is_dir(), "directory does not exist: {}", dir.display());
    Ok(())
}

fn scenario_id_set(summary: &DevnetStatefulSummary) -> BTreeSet<String> {
    summary
        .scenarios
        .iter()
        .map(|scenario| scenario.scenario_id.clone())
        .collect()
}

fn audit_status_cell(status: Option<bool>) -> &'static str {
    match status {
        Some(true) => "passed",
        Some(false) => "missing",
        None => "absent",
    }
}

fn table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smoke_report::{
        DeployedScriptSummary, FactoryLocalExitEvidenceSummary, FactoryMerkleUpdateEvidenceSummary,
        FactoryProofProfileSummary, FactoryReducedExitEvidenceSummary,
        FactoryReducedRightsEvidenceSummary, FactorySpliceEvidenceSummary, MetricTotals,
        SplicePayoutEvidenceSummary, TransactionSummary, WatchtowerAlertSummary,
        WatchtowerServiceSummary,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_bad_audit_profile_schema() {
        let dir = temp_dir("bad-audit-profile-schema");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profile.json");
        fs::write(
            &path,
            r#"{"schema":"wrong","families":[{"id":"f","severity":"P0","principle":"p"}]}"#,
        )
        .unwrap();

        let err = read_audit_profile(&path).unwrap_err();
        assert!(err.to_string().contains("unsupported devnet audit profile"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn audit_family_summary_rejects_unknown_coverage_tag() {
        let summary = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec!["unknown_tag".to_string()],
        });
        let profile = audit_profile(vec![AuditFamilyProfile {
            id: "family-a".to_string(),
            severity: "P0".to_string(),
            principle: "principle".to_string(),
            required_coverage_tags: vec!["known_tag".to_string()],
            required_scenarios: vec![],
            required_committed_checks: vec![],
            required_expected_failures: vec![],
        }]);

        let audit = audit_family_summaries(&summary, &profile);
        assert_eq!(audit.unknown_coverage_tags, vec!["unknown_tag"]);
        let mut checked_summary = summary;
        checked_summary.audit_families = audit.families;
        checked_summary.unknown_coverage_tags = audit.unknown_coverage_tags;
        let err = assert_audit_families(&checked_summary, Some(&profile), None).unwrap_err();
        assert!(err.to_string().contains("unknown coverage tags"));
    }

    #[test]
    fn audit_family_summary_reports_missing_required_evidence() {
        let summary = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec!["family-a".to_string()],
        });
        let expected_failure = StatefulExpectedFailure {
            check: "negative-check".to_string(),
            morph_error: "ExpectedError".to_string(),
            error_code: 42,
        };
        let profile = audit_profile(vec![AuditFamilyProfile {
            id: "family-a".to_string(),
            severity: "P0".to_string(),
            principle: "principle".to_string(),
            required_coverage_tags: vec!["family-a".to_string()],
            required_scenarios: vec!["scenario-b".to_string()],
            required_committed_checks: vec!["committed-check".to_string()],
            required_expected_failures: vec![expected_failure.clone()],
        }]);

        let audit = audit_family_summaries(&summary, &profile);
        let family = &audit.families[0];
        assert!(!family.passed);
        assert_eq!(family.missing_scenarios, vec!["scenario-b"]);
        assert_eq!(family.missing_checks, vec!["committed-check"]);
        assert_eq!(family.missing_failures, vec![expected_failure]);
    }

    #[test]
    fn complete_audit_family_passes() {
        let mut summary = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec!["family-a".to_string()],
        });
        summary.smoke = Some(smoke_summary(
            vec![transaction("committed-check", "Committed")],
            vec![script_failure("negative-check", "ExpectedError", 42)],
        ));
        let profile = audit_profile(vec![AuditFamilyProfile {
            id: "family-a".to_string(),
            severity: "P0".to_string(),
            principle: "principle".to_string(),
            required_coverage_tags: vec!["family-a".to_string()],
            required_scenarios: vec!["scenario-a".to_string()],
            required_committed_checks: vec!["committed-check".to_string()],
            required_expected_failures: vec![StatefulExpectedFailure {
                check: "negative-check".to_string(),
                morph_error: "ExpectedError".to_string(),
                error_code: 42,
            }],
        }]);

        let audit = audit_family_summaries(&summary, &profile);
        assert!(audit.unknown_coverage_tags.is_empty());
        assert!(audit.families[0].passed);
    }

    #[test]
    fn comparison_detects_audit_family_status_regression() {
        let mut baseline = summary_with_scenario(StatefulScenarioSummary {
            scenario_id: "scenario-a".to_string(),
            category: "test".to_string(),
            description: "test".to_string(),
            references: vec!["a.json".to_string()],
            required_committed_checks: vec![],
            expected_failures: vec![],
            coverage: vec![],
        });
        baseline.audit_families = vec![AuditFamilySummary {
            id: "family-a".to_string(),
            severity: "P0".to_string(),
            principle: "principle".to_string(),
            passed: true,
            missing_tags: vec![],
            missing_scenarios: vec![],
            missing_checks: vec![],
            missing_failures: vec![],
        }];
        let mut candidate = baseline.clone();
        candidate.audit_families[0].passed = false;

        let deltas = audit_family_status_deltas(&baseline, &candidate);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].id, "family-a");
        assert_eq!(deltas[0].baseline_passed, Some(true));
        assert_eq!(deltas[0].candidate_passed, Some(false));
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "morph-stateful-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn audit_profile(families: Vec<AuditFamilyProfile>) -> DevnetAuditProfile {
        DevnetAuditProfile {
            schema: DEVNET_AUDIT_PROFILE_SCHEMA.to_string(),
            families,
        }
    }

    fn summary_with_scenario(scenario: StatefulScenarioSummary) -> DevnetStatefulSummary {
        let mut manifest = BTreeMap::new();
        manifest.insert("status".to_string(), "passed".to_string());
        DevnetStatefulSummary {
            directory: ".".to_string(),
            manifest,
            scenarios: vec![scenario],
            audit_families: vec![],
            unknown_coverage_tags: vec![],
            smoke: Some(smoke_summary(vec![], vec![])),
        }
    }

    fn smoke_summary(
        transactions: Vec<TransactionSummary>,
        script_failures: Vec<smoke_report::ScriptFailureSummary>,
    ) -> DevnetSmokeSummary {
        DevnetSmokeSummary {
            directory: ".".to_string(),
            manifest: BTreeMap::new(),
            json_files: 0,
            json_checks: vec![],
            transactions,
            script_failures,
            deployed_scripts: Vec::<DeployedScriptSummary>::new(),
            watchtower_alerts: Vec::<WatchtowerAlertSummary>::new(),
            watchtower_services: Vec::<WatchtowerServiceSummary>::new(),
            factory_reduced_rights_updates: Vec::<FactoryReducedRightsEvidenceSummary>::new(),
            factory_merkle_updates: Vec::<FactoryMerkleUpdateEvidenceSummary>::new(),
            factory_proof_profiles: Vec::<FactoryProofProfileSummary>::new(),
            factory_reduced_exits: Vec::<FactoryReducedExitEvidenceSummary>::new(),
            factory_local_exits: Vec::<FactoryLocalExitEvidenceSummary>::new(),
            factory_splices: Vec::<FactorySpliceEvidenceSummary>::new(),
            splice_payouts: Vec::<SplicePayoutEvidenceSummary>::new(),
            totals: MetricTotals::default(),
        }
    }

    fn transaction(check: &str, status: &str) -> TransactionSummary {
        TransactionSummary {
            check: check.to_string(),
            path: "$.tx".to_string(),
            tx_hash: "0x00".to_string(),
            status: Some(status.to_string()),
            block_number: Some(1),
            estimated_cycles: 1,
            tx_size_bytes: 1,
        }
    }

    fn script_failure(
        check: &str,
        morph_error: &str,
        error_code: i64,
    ) -> smoke_report::ScriptFailureSummary {
        smoke_report::ScriptFailureSummary {
            check: check.to_string(),
            path: "$.failure".to_string(),
            source: Some("stderr".to_string()),
            error_code: Some(error_code),
            morph_error: Some(morph_error.to_string()),
        }
    }
}
