use crate::config::SecurityConfig;
use anyhow::{anyhow, bail, Context, Result};
use getrandom::fill as getrandom_fill;
use std::env;
#[cfg(all(test, unix))]
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const MASTER_KEY_SIZE: usize = 32;
const ROLLBACK_FLOOR_SIZE: usize = 8;
const DEFAULT_TPM_DEVICE_PATHS: [&str; 3] = ["/sys/class/tpm/tpm0", "/dev/tpm0", "/dev/tpmrm0"];
const TPM_HIERARCHY_AUTH_ENV: &str = "AEGIS_LINUX_TPM_HIERARCHY_AUTH";
const TPM_INDEX_AUTH_ENV: &str = "AEGIS_LINUX_TPM_INDEX_AUTH";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LinuxTpmRuntime {
    pub(crate) hardware_present: bool,
    pub(crate) tools_ready: bool,
    pub(crate) master_key_index: Option<String>,
    pub(crate) rollback_index: Option<String>,
    pub(crate) auto_provision: bool,
}

impl LinuxTpmRuntime {
    pub(crate) fn available(&self) -> bool {
        self.hardware_present && self.tools_ready
    }

    pub(crate) fn master_key_enabled(&self) -> bool {
        self.available() && self.master_key_index.is_some()
    }

    pub(crate) fn rollback_enabled(&self) -> bool {
        self.available() && self.rollback_index.is_some()
    }
}

pub(crate) fn detect_linux_tpm_runtime(security: &SecurityConfig) -> LinuxTpmRuntime {
    let hardware_present = security
        .linux_tpm_device_path
        .as_deref()
        .map(Path::exists)
        .unwrap_or_else(|| {
            DEFAULT_TPM_DEVICE_PATHS
                .iter()
                .any(|path| Path::new(path).exists())
        });
    let tools_ready = ["tpm2_nvreadpublic", "tpm2_nvread", "tpm2_nvwrite"]
        .into_iter()
        .all(|tool| resolve_tool(security, tool).is_some())
        && (!security.linux_tpm_auto_provision_nv
            || resolve_tool(security, "tpm2_nvdefine").is_some());

    LinuxTpmRuntime {
        hardware_present,
        tools_ready,
        master_key_index: sanitize_index(security.linux_tpm_master_key_nv_index.as_deref()),
        rollback_index: sanitize_index(security.linux_tpm_rollback_nv_index.as_deref()),
        auto_provision: security.linux_tpm_auto_provision_nv,
    }
}

pub(crate) fn load_or_initialize_master_key_from_tpm(security: &SecurityConfig) -> Result<Vec<u8>> {
    let runtime = detect_linux_tpm_runtime(security);
    if !runtime.available() {
        bail!("linux tpm runtime unavailable");
    }
    let index = runtime
        .master_key_index
        .ok_or_else(|| anyhow!("linux tpm master key nv index not configured"))?;
    let created = ensure_nv_index(security, &index, MASTER_KEY_SIZE)?;
    if created {
        let mut secret = vec![0u8; MASTER_KEY_SIZE];
        getrandom_fill(&mut secret)
            .map_err(|error| anyhow!("generate tpm-backed master key: {error}"))?;
        write_nv_bytes(security, &index, &secret)?;
        return Ok(secret);
    }
    read_nv_bytes(security, &index, MASTER_KEY_SIZE)
}

pub(crate) fn load_or_initialize_rollback_floor_from_tpm(
    security: &SecurityConfig,
) -> Result<Option<i64>> {
    let runtime = detect_linux_tpm_runtime(security);
    if !runtime.available() {
        bail!("linux tpm runtime unavailable");
    }
    let index = runtime
        .rollback_index
        .ok_or_else(|| anyhow!("linux tpm rollback nv index not configured"))?;
    let created = ensure_nv_index(security, &index, ROLLBACK_FLOOR_SIZE)?;
    if created {
        write_nv_bytes(security, &index, &0i64.to_be_bytes())?;
        return Ok(None);
    }
    let bytes = read_nv_bytes(security, &index, ROLLBACK_FLOOR_SIZE)?;
    let mut floor = [0u8; ROLLBACK_FLOOR_SIZE];
    floor.copy_from_slice(&bytes);
    let value = i64::from_be_bytes(floor);
    Ok((value > 0).then_some(value))
}

pub(crate) fn persist_rollback_floor_to_tpm(
    security: &SecurityConfig,
    floor_issued_at_ms: Option<i64>,
) -> Result<()> {
    let runtime = detect_linux_tpm_runtime(security);
    if !runtime.available() {
        bail!("linux tpm runtime unavailable");
    }
    let index = runtime
        .rollback_index
        .ok_or_else(|| anyhow!("linux tpm rollback nv index not configured"))?;
    ensure_nv_index(security, &index, ROLLBACK_FLOOR_SIZE)?;
    write_nv_bytes(
        security,
        &index,
        &floor_issued_at_ms.unwrap_or_default().to_be_bytes(),
    )
}

fn sanitize_index(index: Option<&str>) -> Option<String> {
    index
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn ensure_nv_index(security: &SecurityConfig, index: &str, size: usize) -> Result<bool> {
    if nv_index_exists(security, index)? {
        return Ok(false);
    }
    if !security.linux_tpm_auto_provision_nv {
        bail!("tpm nv index {index} not provisioned");
    }

    let mut command = build_tool_command(security, "tpm2_nvdefine")?;
    command
        .arg(index)
        .arg("-C")
        .arg("o")
        .arg("-s")
        .arg(size.to_string());
    if let Some(auth) = hierarchy_auth() {
        command.arg("-P").arg(auth);
    }
    if let Some(auth) = index_auth() {
        command.arg("-p").arg(auth);
    }
    run_command(command, &format!("define tpm nv index {index}"))?;
    Ok(true)
}

fn nv_index_exists(security: &SecurityConfig, index: &str) -> Result<bool> {
    let output = run_command(
        build_tool_command(security, "tpm2_nvreadpublic")?,
        "enumerate tpm nv indices",
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    Ok(stdout.contains(&index.to_ascii_lowercase()))
}

fn read_nv_bytes(security: &SecurityConfig, index: &str, size: usize) -> Result<Vec<u8>> {
    let mut command = build_tool_command(security, "tpm2_nvread")?;
    command
        .arg(index)
        .arg("-C")
        .arg(index)
        .arg("-s")
        .arg(size.to_string());
    if let Some(auth) = index_auth() {
        command.arg("-P").arg(auth);
    }
    let output = run_command(command, &format!("read tpm nv index {index}"))?;
    if output.stdout.len() != size {
        bail!(
            "unexpected byte length {} from tpm nv index {}, expected {}",
            output.stdout.len(),
            index,
            size
        );
    }
    Ok(output.stdout)
}

fn write_nv_bytes(security: &SecurityConfig, index: &str, bytes: &[u8]) -> Result<()> {
    let mut command = build_tool_command(security, "tpm2_nvwrite")?;
    command
        .arg(index)
        .arg("-C")
        .arg(index)
        .arg("-i-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(auth) = index_auth() {
        command.arg("-P").arg(auth);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn tpm2_nvwrite for {index}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("tpm2_nvwrite stdin unavailable for index {index}"))?;
        stdin
            .write_all(bytes)
            .with_context(|| format!("stream data into tpm2_nvwrite for {index}"))?;
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("wait for tpm2_nvwrite for {index}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "write tpm nv index {} failed with status {}{}",
            index,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    Ok(())
}

fn build_tool_command(security: &SecurityConfig, tool: &str) -> Result<Command> {
    let path = resolve_tool(security, tool).ok_or_else(|| anyhow!("missing tool {tool}"))?;
    Ok(Command::new(path))
}

fn run_command(mut command: Command, context: &str) -> Result<Output> {
    let output = command.output().with_context(|| context.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "{} failed with status {}{}",
            context,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    Ok(output)
}

fn resolve_tool(security: &SecurityConfig, tool: &str) -> Option<PathBuf> {
    if let Some(dir) = &security.linux_tpm_tools_dir {
        let candidate = dir.join(tool);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|entry| entry.join(tool))
            .find(|candidate| candidate.is_file())
    })
}

fn hierarchy_auth() -> Option<String> {
    env::var(TPM_HIERARCHY_AUTH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn index_auth() -> Option<String> {
    env::var(TPM_INDEX_AUTH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(all(test, unix))]
pub(crate) struct TestTpmHarness {
    pub(crate) tools_dir: PathBuf,
    pub(crate) device_path: PathBuf,
}

#[cfg(all(test, unix))]
impl TestTpmHarness {
    pub(crate) fn install(name: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        use uuid::Uuid;

        let root = env::temp_dir().join(format!("aegis-tpm-{name}-{}", Uuid::now_v7()));
        let tools_dir = root.join("tools");
        let store_dir = root.join("store");
        fs::create_dir_all(&tools_dir).expect("create test tpm tools dir");
        fs::create_dir_all(&store_dir).expect("create test tpm store dir");
        let device_path = root.join("dev/tpmrm0");
        fs::create_dir_all(device_path.parent().expect("device dir")).expect("create device dir");
        fs::write(&device_path, b"simulated-tpm").expect("create fake tpm device");

        for tool in [
            "tpm2_nvreadpublic",
            "tpm2_nvdefine",
            "tpm2_nvread",
            "tpm2_nvwrite",
        ] {
            let path = tools_dir.join(tool);
            fs::write(&path, test_tool_script(tool, &store_dir)).expect("write test tool");
            let mut permissions = fs::metadata(&path).expect("stat tool").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("chmod tool");
        }

        Self {
            tools_dir,
            device_path,
        }
    }
}

#[cfg(all(test, unix))]
fn test_tool_script(tool: &str, store_dir: &Path) -> String {
    format!(
        r#"#!/bin/sh
set -eu
STORE="{store}"
tool="{tool}"

case "$tool" in
  tpm2_nvreadpublic)
    found=0
    for file in "$STORE"/*.bin; do
      if [ -e "$file" ]; then
        index=$(basename "$file" .bin)
        size=$(wc -c < "$file" | tr -d ' ')
        printf '%s:\n  size: %s\n' "$index" "$size"
        found=1
      fi
    done
    if [ "$found" -eq 0 ]; then
      exit 0
    fi
    ;;
  tpm2_nvdefine)
    index="$1"
    shift
    size=0
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -s)
          size="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    dd if=/dev/zero of="$STORE/$index.bin" bs=1 count="$size" 2>/dev/null
    printf '%s\n' "$index"
    ;;
  tpm2_nvread)
    index="$1"
    shift
    size=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -s)
          size="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [ -n "$size" ]; then
      head -c "$size" "$STORE/$index.bin"
    else
      cat "$STORE/$index.bin"
    fi
    ;;
  tpm2_nvwrite)
    index="$1"
    shift
    input_mode=stdin
    input_path=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -i-)
          input_mode=stdin
          shift
          ;;
        -i)
          input_mode=file
          input_path="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [ "$input_mode" = file ]; then
      cat "$input_path" > "$STORE/$index.bin"
    else
      cat > "$STORE/$index.bin"
    fi
    ;;
esac
"#,
        store = store_dir.display(),
        tool = tool,
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        detect_linux_tpm_runtime, load_or_initialize_master_key_from_tpm,
        load_or_initialize_rollback_floor_from_tpm, persist_rollback_floor_to_tpm, TestTpmHarness,
    };
    use crate::config::SecurityConfig;

    #[test]
    fn detect_runtime_respects_explicit_tool_dir_and_device_override() {
        let harness = TestTpmHarness::install("detect-runtime");
        let security = SecurityConfig {
            linux_tpm_tools_dir: Some(harness.tools_dir),
            linux_tpm_device_path: Some(harness.device_path),
            linux_tpm_master_key_nv_index: Some("0x1500016".to_string()),
            linux_tpm_rollback_nv_index: Some("0x1500017".to_string()),
            ..SecurityConfig::default()
        };

        let runtime = detect_linux_tpm_runtime(&security);
        assert!(runtime.available());
        assert!(runtime.master_key_enabled());
        assert!(runtime.rollback_enabled());
    }

    #[test]
    fn master_key_round_trips_through_tpm_nv_index() {
        let harness = TestTpmHarness::install("master-key");
        let security = SecurityConfig {
            linux_tpm_tools_dir: Some(harness.tools_dir),
            linux_tpm_device_path: Some(harness.device_path),
            linux_tpm_master_key_nv_index: Some("0x1500018".to_string()),
            linux_tpm_auto_provision_nv: true,
            ..SecurityConfig::default()
        };

        let first =
            load_or_initialize_master_key_from_tpm(&security).expect("provision master key");
        let second = load_or_initialize_master_key_from_tpm(&security).expect("reload master key");

        assert_eq!(first.len(), 32);
        assert_eq!(first, second);
    }

    #[test]
    fn rollback_floor_round_trips_through_tpm_nv_index() {
        let harness = TestTpmHarness::install("rollback-floor");
        let security = SecurityConfig {
            linux_tpm_tools_dir: Some(harness.tools_dir),
            linux_tpm_device_path: Some(harness.device_path),
            linux_tpm_rollback_nv_index: Some("0x1500019".to_string()),
            linux_tpm_auto_provision_nv: true,
            ..SecurityConfig::default()
        };

        assert_eq!(
            load_or_initialize_rollback_floor_from_tpm(&security).expect("load initial floor"),
            None
        );

        persist_rollback_floor_to_tpm(&security, Some(42_000)).expect("persist floor");
        assert_eq!(
            load_or_initialize_rollback_floor_from_tpm(&security).expect("reload floor"),
            Some(42_000)
        );
    }
}
