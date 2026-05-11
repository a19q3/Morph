use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::devnet::{
    WatchLatestStatePackageOptions, WatchLatestStatePackageReport, watch_latest_state_package,
};
use crate::packages::canonical_hex32;
use crate::rpc::CkbRpcClient;

const WATCH_CONFIG_SCHEMA: &str = "morph.watchtower_config.v1";
const WATCH_CONFIG_RUN_SCHEMA: &str = "morph.watchtower_config_run.v1";
const DEFAULT_STORE_DIR: &str = "target/morph-state-packages";
const DEFAULT_DETECTION_DEPTH: u64 = 1;
const DEFAULT_TIMEOUT_SECS: u64 = 60;
const DEFAULT_POLL_MS: u64 = 1_000;
const DEFAULT_FEE: u64 = 100_000_000;
const DEFAULT_MINE_BLOCKS: u64 = 4;
const DEFAULT_AUTO_SPONSOR_CAPACITY: u64 = 50_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerConfigV1 {
    pub schema: String,
    #[serde(default)]
    pub defaults: WatchtowerConfigDefaults,
    pub channels: Vec<WatchtowerChannelConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerConfigDefaults {
    pub store_dir: Option<PathBuf>,
    pub watch_policy: Option<PathBuf>,
    pub alert_file: Option<PathBuf>,
    pub alert_webhook_url: Option<String>,
    pub detection_depth: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub poll_ms: Option<u64>,
    pub fee: Option<u64>,
    pub mine_blocks: Option<u64>,
    pub auto_fund_sponsor: Option<bool>,
    pub auto_sponsor_capacity: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerChannelConfig {
    pub channel_id: String,
    #[serde(default)]
    pub from_block: u64,
    pub sponsor_out_point: Option<String>,
    pub store_dir: Option<PathBuf>,
    pub cursor_file: Option<PathBuf>,
    pub watch_policy: Option<PathBuf>,
    pub alert_file: Option<PathBuf>,
    pub alert_webhook_url: Option<String>,
    pub detection_depth: Option<u64>,
    pub timeout_secs: Option<u64>,
    pub poll_ms: Option<u64>,
    pub fee: Option<u64>,
    pub mine_blocks: Option<u64>,
    pub auto_fund_sponsor: Option<bool>,
    pub auto_sponsor_capacity: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct WatchtowerRuntimeOptions {
    pub contracts_dir: PathBuf,
    pub private_key: String,
}

#[derive(Debug, Serialize)]
pub struct WatchtowerConfigRunReport {
    pub schema: String,
    pub config_path: String,
    pub channel_count: usize,
    pub published_count: usize,
    pub idle_count: usize,
    pub channels: Vec<WatchtowerChannelRunReport>,
}

#[derive(Debug, Serialize)]
pub struct WatchtowerChannelRunReport {
    pub channel_id: String,
    pub report: WatchLatestStatePackageReport,
}

impl WatchtowerConfigV1 {
    pub fn fixture() -> Self {
        Self {
            schema: WATCH_CONFIG_SCHEMA.to_string(),
            defaults: WatchtowerConfigDefaults {
                store_dir: Some(PathBuf::from("target/morph-state-packages")),
                watch_policy: Some(PathBuf::from("target/watch-policy.json")),
                alert_file: Some(PathBuf::from("target/watch-alerts.jsonl")),
                alert_webhook_url: None,
                detection_depth: Some(3),
                timeout_secs: Some(30),
                poll_ms: Some(1_000),
                fee: Some(DEFAULT_FEE),
                mine_blocks: Some(DEFAULT_MINE_BLOCKS),
                auto_fund_sponsor: Some(true),
                auto_sponsor_capacity: Some(DEFAULT_AUTO_SPONSOR_CAPACITY),
            },
            channels: vec![WatchtowerChannelConfig {
                channel_id: "0x1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                from_block: 0,
                sponsor_out_point: None,
                store_dir: None,
                cursor_file: None,
                watch_policy: None,
                alert_file: None,
                alert_webhook_url: None,
                detection_depth: None,
                timeout_secs: None,
                poll_ms: None,
                fee: None,
                mine_blocks: None,
                auto_fund_sponsor: None,
                auto_sponsor_capacity: None,
            }],
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == WATCH_CONFIG_SCHEMA,
            "unsupported watchtower config schema {}",
            self.schema
        );
        ensure!(
            !self.channels.is_empty(),
            "watchtower config must contain at least one channel"
        );
        ensure_positive(self.defaults.detection_depth, "default detection_depth")?;
        ensure_positive(self.defaults.timeout_secs, "default timeout_secs")?;
        ensure_positive(self.defaults.poll_ms, "default poll_ms")?;
        ensure_positive(self.defaults.fee, "default fee")?;
        ensure_positive(
            self.defaults.auto_sponsor_capacity,
            "default auto_sponsor_capacity",
        )?;

        let mut seen = BTreeSet::new();
        for channel in &self.channels {
            let canonical = canonical_hex32(&channel.channel_id)
                .context("watchtower config channel_id must be canonical hex32")?;
            ensure!(
                channel.channel_id == canonical,
                "watchtower config channel_id must be canonical"
            );
            ensure!(
                seen.insert(canonical.clone()),
                "watchtower config contains duplicate channel {}",
                channel.channel_id
            );
            ensure_positive(channel.detection_depth, "channel detection_depth")?;
            ensure_positive(channel.timeout_secs, "channel timeout_secs")?;
            ensure_positive(channel.poll_ms, "channel poll_ms")?;
            ensure_positive(channel.fee, "channel fee")?;
            ensure_positive(
                channel.auto_sponsor_capacity,
                "channel auto_sponsor_capacity",
            )?;

            let auto_fund_sponsor = channel
                .auto_fund_sponsor
                .or(self.defaults.auto_fund_sponsor)
                .unwrap_or(false);
            ensure!(
                channel.sponsor_out_point.is_some() || auto_fund_sponsor,
                "watchtower channel {} needs sponsor_out_point or auto_fund_sponsor",
                channel.channel_id
            );
            ensure!(
                channel.sponsor_out_point.is_none() || !auto_fund_sponsor,
                "watchtower channel {} must not combine sponsor_out_point with auto_fund_sponsor",
                channel.channel_id
            );
            let mine_blocks = channel
                .mine_blocks
                .or(self.defaults.mine_blocks)
                .unwrap_or(DEFAULT_MINE_BLOCKS);
            ensure!(
                !auto_fund_sponsor || mine_blocks > 0,
                "watchtower channel {} auto sponsor requires mine_blocks greater than zero",
                channel.channel_id
            );
        }
        Ok(())
    }
}

pub fn fixture_config() -> WatchtowerConfigV1 {
    WatchtowerConfigV1::fixture()
}

pub fn read_watchtower_config(path: &Path) -> Result<WatchtowerConfigV1> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read watchtower config {}", path.display()))?;
    let config: WatchtowerConfigV1 = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse watchtower config {}", path.display()))?;
    config
        .validate()
        .with_context(|| format!("invalid watchtower config {}", path.display()))?;
    Ok(config)
}

pub fn run_watchtower_config_once(
    rpc: &CkbRpcClient,
    config_path: &Path,
    config: &WatchtowerConfigV1,
    runtime: WatchtowerRuntimeOptions,
) -> Result<WatchtowerConfigRunReport> {
    config.validate()?;
    let base_dir = config_base_dir(config_path);
    let mut reports = Vec::with_capacity(config.channels.len());
    for channel in &config.channels {
        let options = channel_options(&base_dir, &config.defaults, channel, &runtime)?;
        let report = watch_latest_state_package(rpc, options)
            .with_context(|| format!("failed to watch channel {}", channel.channel_id))?;
        reports.push(WatchtowerChannelRunReport {
            channel_id: channel.channel_id.clone(),
            report,
        });
    }
    let published_count = reports
        .iter()
        .filter(|channel| channel.report.publication.is_some())
        .count();
    Ok(WatchtowerConfigRunReport {
        schema: WATCH_CONFIG_RUN_SCHEMA.to_string(),
        config_path: config_path.display().to_string(),
        channel_count: reports.len(),
        published_count,
        idle_count: reports.len().saturating_sub(published_count),
        channels: reports,
    })
}

fn channel_options(
    base_dir: &Path,
    defaults: &WatchtowerConfigDefaults,
    channel: &WatchtowerChannelConfig,
    runtime: &WatchtowerRuntimeOptions,
) -> Result<WatchLatestStatePackageOptions> {
    Ok(WatchLatestStatePackageOptions {
        contracts_dir: runtime.contracts_dir.clone(),
        private_key: runtime.private_key.clone(),
        sponsor_out_point: channel.sponsor_out_point.clone(),
        store_dir: resolve_path(
            base_dir,
            channel
                .store_dir
                .as_ref()
                .or(defaults.store_dir.as_ref())
                .cloned()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STORE_DIR)),
        ),
        channel_id: channel.channel_id.clone(),
        from_block: channel.from_block,
        cursor_file: optional_resolved_path(base_dir, channel.cursor_file.as_ref()),
        watch_policy: optional_resolved_path(
            base_dir,
            channel
                .watch_policy
                .as_ref()
                .or(defaults.watch_policy.as_ref()),
        ),
        alert_file: optional_resolved_path(
            base_dir,
            channel.alert_file.as_ref().or(defaults.alert_file.as_ref()),
        ),
        alert_webhook_url: channel
            .alert_webhook_url
            .clone()
            .or_else(|| defaults.alert_webhook_url.clone()),
        ignore_cursor: false,
        detection_depth: channel
            .detection_depth
            .or(defaults.detection_depth)
            .unwrap_or(DEFAULT_DETECTION_DEPTH),
        timeout_secs: channel
            .timeout_secs
            .or(defaults.timeout_secs)
            .unwrap_or(DEFAULT_TIMEOUT_SECS),
        poll_ms: channel
            .poll_ms
            .or(defaults.poll_ms)
            .unwrap_or(DEFAULT_POLL_MS),
        fee: channel.fee.or(defaults.fee).unwrap_or(DEFAULT_FEE),
        mine_blocks: channel
            .mine_blocks
            .or(defaults.mine_blocks)
            .unwrap_or(DEFAULT_MINE_BLOCKS),
        auto_fund_sponsor: channel
            .auto_fund_sponsor
            .or(defaults.auto_fund_sponsor)
            .unwrap_or(false),
        auto_sponsor_capacity: channel
            .auto_sponsor_capacity
            .or(defaults.auto_sponsor_capacity)
            .unwrap_or(DEFAULT_AUTO_SPONSOR_CAPACITY),
    })
}

fn ensure_positive(value: Option<u64>, field: &str) -> Result<()> {
    if let Some(value) = value {
        ensure!(value > 0, "{field} must be non-zero");
    }
    Ok(())
}

fn config_base_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn optional_resolved_path(base_dir: &Path, path: Option<&PathBuf>) -> Option<PathBuf> {
    path.cloned().map(|path| resolve_path(base_dir, path))
}

fn resolve_path(base_dir: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_fixture_config() {
        let config = WatchtowerConfigV1::fixture();
        config.validate().unwrap();
        assert_eq!(config.channels.len(), 1);
    }

    #[test]
    fn rejects_duplicate_channels() {
        let mut config = WatchtowerConfigV1::fixture();
        config.channels.push(config.channels[0].clone());
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate channel"));
    }

    #[test]
    fn rejects_channel_without_sponsor_path() {
        let mut config = WatchtowerConfigV1::fixture();
        config.defaults.auto_fund_sponsor = Some(false);
        config.channels[0].sponsor_out_point = None;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("needs sponsor_out_point"));
    }

    #[test]
    fn resolves_channel_options_relative_to_config_file() {
        let mut config = WatchtowerConfigV1::fixture();
        config.defaults.store_dir = Some(PathBuf::from("packages"));
        config.defaults.watch_policy = Some(PathBuf::from("policy.json"));
        config.defaults.alert_file = Some(PathBuf::from("alerts.jsonl"));
        config.channels[0].cursor_file = Some(PathBuf::from("cursor.json"));
        let runtime = WatchtowerRuntimeOptions {
            contracts_dir: PathBuf::from("contracts"),
            private_key: "key".to_string(),
        };
        let options = channel_options(
            Path::new("/tmp/morph-watch"),
            &config.defaults,
            &config.channels[0],
            &runtime,
        )
        .unwrap();
        assert_eq!(
            options.store_dir,
            PathBuf::from("/tmp/morph-watch/packages")
        );
        assert_eq!(
            options.watch_policy,
            Some(PathBuf::from("/tmp/morph-watch/policy.json"))
        );
        assert_eq!(
            options.alert_file,
            Some(PathBuf::from("/tmp/morph-watch/alerts.jsonl"))
        );
        assert_eq!(
            options.cursor_file,
            Some(PathBuf::from("/tmp/morph-watch/cursor.json"))
        );
    }
}
