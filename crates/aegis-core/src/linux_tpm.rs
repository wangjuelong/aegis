use crate::config::SecurityConfig;
use anyhow::{anyhow, bail, Context, Result};
use getrandom::fill as getrandom_fill;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use uuid::Uuid;

const MASTER_KEY_SIZE: usize = 32;
const ROLLBACK_FLOOR_SIZE: usize = 8;
const DEFAULT_TPM_DEVICE_PATHS: [&str; 3] = ["/sys/class/tpm/tpm0", "/dev/tpm0", "/dev/tpmrm0"];
const TPM_HIERARCHY_AUTH_ENV: &str = "AEGIS_LINUX_TPM_HIERARCHY_AUTH";
const TPM_INDEX_AUTH_ENV: &str = "AEGIS_LINUX_TPM_INDEX_AUTH";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LinuxTpmRuntime {
    pub(crate) hardware_present: bool,
    pub(crate) nv_tools_ready: bool,
    pub(crate) sealed_object_tools_ready: bool,
    pub(crate) quote_tools_ready: bool,
    pub(crate) attestation_ak_path: Option<PathBuf>,
    pub(crate) attestation_pcrs: Option<String>,
    pub(crate) master_key_sealed_object_path: Option<PathBuf>,
    pub(crate) master_key_index: Option<String>,
    pub(crate) rollback_index: Option<String>,
    pub(crate) auto_provision: bool,
}

impl LinuxTpmRuntime {
    pub(crate) fn available(&self) -> bool {
        self.nv_available() || self.sealed_object_available()
    }

    pub(crate) fn nv_available(&self) -> bool {
        self.hardware_present && self.nv_tools_ready
    }

    pub(crate) fn sealed_object_available(&self) -> bool {
        self.hardware_present && self.sealed_object_tools_ready
    }

    pub(crate) fn quote_available(&self) -> bool {
        self.hardware_present && self.quote_tools_ready
    }

    pub(crate) fn master_key_configured(&self) -> bool {
        self.master_key_sealed_object_path.is_some() || self.master_key_index.is_some()
    }

    pub(crate) fn attestation_configured(&self) -> bool {
        self.attestation_ak_path.is_some() || self.attestation_pcrs.is_some()
    }

    pub(crate) fn attestation_enabled(&self) -> bool {
        self.quote_available()
            && self.attestation_ak_path.is_some()
            && self.attestation_pcrs.is_some()
    }

    pub(crate) fn attestation_status_error(&self) -> Option<String> {
        if !self.attestation_configured() {
            return None;
        }
        if self.attestation_ak_path.is_none() || self.attestation_pcrs.is_none() {
            return Some(
                "linux tpm attestation requires both ak path and pcr selection".to_string(),
            );
        }
        if !self.quote_available() {
            return Some(
                "linux tpm attestation is configured but quote tools or device are unavailable"
                    .to_string(),
            );
        }
        None
    }

    pub(crate) fn rollback_configured(&self) -> bool {
        self.rollback_index.is_some()
    }

    pub(crate) fn master_key_sealed_enabled(&self) -> bool {
        self.sealed_object_available() && self.master_key_sealed_object_path.is_some()
    }

    pub(crate) fn master_key_nv_enabled(&self) -> bool {
        self.nv_available() && self.master_key_index.is_some()
    }

    pub(crate) fn master_key_enabled(&self) -> bool {
        self.master_key_sealed_enabled() || self.master_key_nv_enabled()
    }

    pub(crate) fn rollback_enabled(&self) -> bool {
        self.nv_available() && self.rollback_index.is_some()
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
    let nv_tools_ready = ["tpm2_nvreadpublic", "tpm2_nvread", "tpm2_nvwrite"]
        .into_iter()
        .all(|tool| resolve_tool(security, tool).is_some())
        && (!security.linux_tpm_auto_provision_nv
            || resolve_tool(security, "tpm2_nvdefine").is_some());
    let sealed_object_tools_ready = [
        "tpm2_createprimary",
        "tpm2_create",
        "tpm2_load",
        "tpm2_unseal",
    ]
    .into_iter()
    .all(|tool| resolve_tool(security, tool).is_some());
    let quote_tools_ready = [
        "tpm2_createek",
        "tpm2_createak",
        "tpm2_quote",
        "tpm2_checkquote",
    ]
    .into_iter()
    .all(|tool| resolve_tool(security, tool).is_some());

    LinuxTpmRuntime {
        hardware_present,
        nv_tools_ready,
        sealed_object_tools_ready,
        quote_tools_ready,
        attestation_ak_path: security.linux_tpm_attestation_ak_path.clone(),
        attestation_pcrs: sanitize_pcrs(security.linux_tpm_attestation_pcrs.as_deref()),
        master_key_sealed_object_path: security.linux_tpm_master_key_sealed_object_path.clone(),
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
    let mut failures = Vec::new();

    if let Some(sealed_object_path) = runtime.master_key_sealed_object_path.as_deref() {
        if runtime.sealed_object_available() {
            match load_or_initialize_master_key_from_tpm_sealed_object(security, sealed_object_path)
            {
                Ok(secret) => return Ok(secret),
                Err(error) => failures.push(format!("sealed object provider failed: {error}")),
            }
        } else {
            failures.push(
                "sealed object provider configured but required tools are unavailable".to_string(),
            );
        }
    }

    if let Some(index) = runtime.master_key_index.as_deref() {
        if runtime.nv_available() {
            match load_or_initialize_master_key_from_tpm_nv_index(security, index) {
                Ok(secret) => return Ok(secret),
                Err(error) => failures.push(format!("nv index provider failed: {error}")),
            }
        } else {
            failures.push(
                "nv index provider configured but required tools are unavailable".to_string(),
            );
        }
    }

    if failures.is_empty() {
        bail!("linux tpm master key provider not configured")
    } else {
        bail!(failures.join("; "))
    }
}

pub(crate) fn load_or_initialize_rollback_floor_from_tpm(
    security: &SecurityConfig,
) -> Result<Option<i64>> {
    let runtime = detect_linux_tpm_runtime(security);
    if !runtime.nv_available() {
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
    if !runtime.nv_available() {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinuxTpmQuoteBundle {
    pub(crate) pcrs: String,
    pub(crate) qualification: Vec<u8>,
    pub(crate) ak_public: Vec<u8>,
    pub(crate) message: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) pcr: Vec<u8>,
}

pub(crate) fn generate_attestation_quote(
    security: &SecurityConfig,
    qualification: &[u8],
) -> Result<LinuxTpmQuoteBundle> {
    let runtime = detect_linux_tpm_runtime(security);
    if !runtime.quote_available() {
        bail!("linux tpm quote runtime unavailable");
    }
    let ak_base_path = runtime
        .attestation_ak_path
        .as_deref()
        .ok_or_else(|| anyhow!("linux tpm attestation ak path not configured"))?;
    let pcrs = runtime
        .attestation_pcrs
        .clone()
        .ok_or_else(|| anyhow!("linux tpm attestation pcr selection not configured"))?;

    let parent = ak_base_path
        .parent()
        .ok_or_else(|| anyhow!("attestation ak path has no parent directory"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create attestation ak dir {}", parent.display()))?;

    let temp_dir = temp_runtime_dir("quote")?;
    let ek_ctx = temp_dir.join("ek.ctx");
    let ek_pub = temp_dir.join("ek.pub");
    let ak_ctx = temp_dir.join("ak.ctx");
    let qualification_path = temp_dir.join("qualification.bin");
    let message_path = temp_dir.join("quote.msg");
    let signature_path = temp_dir.join("quote.sig");
    let pcr_path = temp_dir.join("quote.pcr");
    let (ak_public_path, ak_private_path, ak_name_path) =
        attestation_key_artifact_paths(ak_base_path);
    fs::write(&qualification_path, qualification).with_context(|| {
        format!(
            "write attestation quote qualification {}",
            qualification_path.display()
        )
    })?;

    let result = (|| -> Result<LinuxTpmQuoteBundle> {
        let mut create_ek = build_tool_command(security, "tpm2_createek")?;
        create_ek.arg("-c").arg(&ek_ctx).arg("-u").arg(&ek_pub);
        if let Some(auth) = hierarchy_auth() {
            create_ek.arg("-P").arg(auth);
        }
        run_command(create_ek, "create tpm endorsement key for quote")?;

        let mut create_ak = build_tool_command(security, "tpm2_createak")?;
        create_ak
            .arg("-C")
            .arg(&ek_ctx)
            .arg("-c")
            .arg(&ak_ctx)
            .arg("-u")
            .arg(&ak_public_path)
            .arg("-r")
            .arg(&ak_private_path)
            .arg("-n")
            .arg(&ak_name_path)
            .arg("-G")
            .arg("rsa")
            .arg("-g")
            .arg("sha256")
            .arg("-s")
            .arg("rsassa");
        run_command(create_ak, "create tpm attestation key")?;

        let mut quote = build_tool_command(security, "tpm2_quote")?;
        quote
            .arg("-c")
            .arg(&ak_ctx)
            .arg("-l")
            .arg(&pcrs)
            .arg("-q")
            .arg(&qualification_path)
            .arg("-m")
            .arg(&message_path)
            .arg("-s")
            .arg(&signature_path)
            .arg("-o")
            .arg(&pcr_path);
        run_command(quote, "generate tpm attestation quote")?;

        Ok(LinuxTpmQuoteBundle {
            pcrs,
            qualification: qualification.to_vec(),
            ak_public: fs::read(&ak_public_path).with_context(|| {
                format!("read attestation ak public {}", ak_public_path.display())
            })?,
            message: fs::read(&message_path).with_context(|| {
                format!("read attestation quote message {}", message_path.display())
            })?,
            signature: fs::read(&signature_path).with_context(|| {
                format!(
                    "read attestation quote signature {}",
                    signature_path.display()
                )
            })?,
            pcr: fs::read(&pcr_path)
                .with_context(|| format!("read attestation quote pcr {}", pcr_path.display()))?,
        })
    })();

    best_effort_flush_context(security, &ak_ctx);
    best_effort_flush_context(security, &ek_ctx);
    let _ = fs::remove_dir_all(&temp_dir);
    result
}

pub(crate) fn verify_attestation_quote(
    security: &SecurityConfig,
    quote: &LinuxTpmQuoteBundle,
) -> Result<()> {
    let runtime = detect_linux_tpm_runtime(security);
    if !runtime.quote_available() {
        bail!("linux tpm quote runtime unavailable");
    }

    let temp_dir = temp_runtime_dir("checkquote")?;
    let ak_public_path = temp_dir.join("ak.pub");
    let qualification_path = temp_dir.join("qualification.bin");
    let message_path = temp_dir.join("quote.msg");
    let signature_path = temp_dir.join("quote.sig");
    let pcr_path = temp_dir.join("quote.pcr");

    let result = (|| -> Result<()> {
        fs::write(&ak_public_path, &quote.ak_public)
            .with_context(|| format!("write attestation ak public {}", ak_public_path.display()))?;
        fs::write(&qualification_path, &quote.qualification).with_context(|| {
            format!(
                "write attestation quote qualification {}",
                qualification_path.display()
            )
        })?;
        fs::write(&message_path, &quote.message).with_context(|| {
            format!("write attestation quote message {}", message_path.display())
        })?;
        fs::write(&signature_path, &quote.signature).with_context(|| {
            format!(
                "write attestation quote signature {}",
                signature_path.display()
            )
        })?;
        fs::write(&pcr_path, &quote.pcr)
            .with_context(|| format!("write attestation quote pcr {}", pcr_path.display()))?;

        let mut checkquote = build_tool_command(security, "tpm2_checkquote")?;
        checkquote
            .arg("-u")
            .arg(&ak_public_path)
            .arg("-m")
            .arg(&message_path)
            .arg("-s")
            .arg(&signature_path)
            .arg("-f")
            .arg(&pcr_path)
            .arg("-g")
            .arg("sha256")
            .arg("-q")
            .arg(&qualification_path);
        run_command(checkquote, "verify tpm attestation quote")?;
        Ok(())
    })();

    let _ = fs::remove_dir_all(&temp_dir);
    result
}

fn sanitize_index(index: Option<&str>) -> Option<String> {
    index
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn sanitize_pcrs(pcrs: Option<&str>) -> Option<String> {
    pcrs.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn load_or_initialize_master_key_from_tpm_nv_index(
    security: &SecurityConfig,
    index: &str,
) -> Result<Vec<u8>> {
    let created = ensure_nv_index(security, index, MASTER_KEY_SIZE)?;
    if created {
        let secret = generate_master_key_secret()?;
        write_nv_bytes(security, index, &secret)?;
        return Ok(secret);
    }
    read_nv_bytes(security, index, MASTER_KEY_SIZE)
}

fn load_or_initialize_master_key_from_tpm_sealed_object(
    security: &SecurityConfig,
    sealed_object_path: &Path,
) -> Result<Vec<u8>> {
    let (public_path, private_path) = sealed_object_artifact_paths(sealed_object_path);
    if public_path.exists() && private_path.exists() {
        return unseal_master_key_from_sealed_object(security, &public_path, &private_path);
    }

    if public_path.exists() != private_path.exists() {
        let _ = fs::remove_file(&public_path);
        let _ = fs::remove_file(&private_path);
    }

    let secret = generate_master_key_secret()?;
    create_sealed_object(security, &public_path, &private_path, &secret)?;
    Ok(secret)
}

fn generate_master_key_secret() -> Result<Vec<u8>> {
    let mut secret = vec![0u8; MASTER_KEY_SIZE];
    getrandom_fill(&mut secret)
        .map_err(|error| anyhow!("generate tpm-backed master key: {error}"))?;
    Ok(secret)
}

fn create_sealed_object(
    security: &SecurityConfig,
    public_path: &Path,
    private_path: &Path,
    secret: &[u8],
) -> Result<()> {
    let parent = public_path
        .parent()
        .or_else(|| private_path.parent())
        .ok_or_else(|| anyhow!("sealed object path has no parent directory"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create sealed object dir {}", parent.display()))?;

    let temp_dir = temp_runtime_dir("create")?;
    let secret_path = temp_dir.join("secret.bin");
    let primary_ctx = temp_dir.join("primary.ctx");
    fs::write(&secret_path, secret)
        .with_context(|| format!("write sealed object input {}", secret_path.display()))?;

    let result = (|| -> Result<()> {
        let mut create_primary = build_tool_command(security, "tpm2_createprimary")?;
        create_primary
            .arg("-C")
            .arg("o")
            .arg("-c")
            .arg(&primary_ctx);
        if let Some(auth) = hierarchy_auth() {
            create_primary.arg("-P").arg(auth);
        }
        run_command(create_primary, "create tpm primary for sealed object")?;

        let mut create = build_tool_command(security, "tpm2_create")?;
        create
            .arg("-C")
            .arg(&primary_ctx)
            .arg("-u")
            .arg(public_path)
            .arg("-r")
            .arg(private_path)
            .arg("-i")
            .arg(&secret_path);
        run_command(create, "create sealed tpm object")?;
        Ok(())
    })();

    best_effort_flush_context(security, &primary_ctx);
    let _ = fs::remove_dir_all(&temp_dir);
    result
}

fn unseal_master_key_from_sealed_object(
    security: &SecurityConfig,
    public_path: &Path,
    private_path: &Path,
) -> Result<Vec<u8>> {
    let temp_dir = temp_runtime_dir("unseal")?;
    let primary_ctx = temp_dir.join("primary.ctx");
    let object_ctx = temp_dir.join("object.ctx");

    let result = (|| -> Result<Vec<u8>> {
        let mut create_primary = build_tool_command(security, "tpm2_createprimary")?;
        create_primary
            .arg("-C")
            .arg("o")
            .arg("-c")
            .arg(&primary_ctx);
        if let Some(auth) = hierarchy_auth() {
            create_primary.arg("-P").arg(auth);
        }
        run_command(create_primary, "create tpm primary for unseal")?;

        let mut load = build_tool_command(security, "tpm2_load")?;
        load.arg("-C")
            .arg(&primary_ctx)
            .arg("-u")
            .arg(public_path)
            .arg("-r")
            .arg(private_path)
            .arg("-c")
            .arg(&object_ctx);
        run_command(load, "load sealed tpm object")?;

        let mut unseal = build_tool_command(security, "tpm2_unseal")?;
        unseal.arg("-c").arg(&object_ctx);
        let output = run_command(unseal, "unseal tpm master key")?;
        let secret = output.stdout;
        if secret.len() != MASTER_KEY_SIZE {
            bail!(
                "unexpected master key length {} from sealed object, expected {}",
                secret.len(),
                MASTER_KEY_SIZE
            );
        }
        Ok(secret)
    })();

    best_effort_flush_context(security, &object_ctx);
    best_effort_flush_context(security, &primary_ctx);
    let _ = fs::remove_dir_all(&temp_dir);
    result
}

fn sealed_object_artifact_paths(base_path: &Path) -> (PathBuf, PathBuf) {
    (
        path_with_suffix(base_path, ".pub"),
        path_with_suffix(base_path, ".priv"),
    )
}

fn attestation_key_artifact_paths(base_path: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        path_with_suffix(base_path, ".pub"),
        path_with_suffix(base_path, ".priv"),
        path_with_suffix(base_path, ".name"),
    )
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

fn temp_runtime_dir(scope: &str) -> Result<PathBuf> {
    let dir = env::temp_dir().join(format!("aegis-linux-tpm-{scope}-{}", Uuid::now_v7()));
    fs::create_dir_all(&dir).with_context(|| format!("create temp tpm dir {}", dir.display()))?;
    Ok(dir)
}

fn best_effort_flush_context(security: &SecurityConfig, context_path: &Path) {
    let Some(flush_path) = resolve_tool(security, "tpm2_flushcontext") else {
        return;
    };

    let mut command = Command::new(flush_path);
    apply_tcti_override(security, &mut command);
    let _ = command.arg(context_path).output();
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
    let mut command = Command::new(path);
    apply_tcti_override(security, &mut command);
    Ok(command)
}

fn apply_tcti_override(security: &SecurityConfig, command: &mut Command) {
    let Some(device_path) = security.linux_tpm_device_path.as_deref() else {
        return;
    };
    if !device_path.starts_with("/dev/") {
        return;
    }
    command.env(
        "TPM2TOOLS_TCTI",
        format!("device:{}", device_path.display()),
    );
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
            "tpm2_createek",
            "tpm2_createak",
            "tpm2_quote",
            "tpm2_checkquote",
            "tpm2_createprimary",
            "tpm2_create",
            "tpm2_load",
            "tpm2_unseal",
            "tpm2_flushcontext",
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

to_hex() {{
  od -An -tx1 -v "$1" | tr -d ' \n'
}}

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
  tpm2_createek)
    context=
    public=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -c)
          context="$2"
          shift 2
          ;;
        -u)
          public="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    printf 'ek' > "$context"
    printf 'ek-public' > "$public"
    ;;
  tpm2_createak)
    context=
    public=
    private=
    name=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -c)
          context="$2"
          shift 2
          ;;
        -u)
          public="$2"
          shift 2
          ;;
        -r)
          private="$2"
          shift 2
          ;;
        -n)
          name="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    printf 'ak' > "$context"
    printf 'ak-public' > "$public"
    printf 'ak-private' > "$private"
    printf 'ak-name' > "$name"
    ;;
  tpm2_quote)
    qualification=
    message=
    signature=
    pcr=
    pcr_list=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -q)
          qualification="$2"
          shift 2
          ;;
        -m)
          message="$2"
          shift 2
          ;;
        -s)
          signature="$2"
          shift 2
          ;;
        -o)
          pcr="$2"
          shift 2
          ;;
        -l)
          pcr_list="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    qualification_hex=$(to_hex "$qualification")
    printf 'quote:%s:%s' "$pcr_list" "$qualification_hex" > "$message"
    printf 'sig:%s:%s' "$pcr_list" "$qualification_hex" > "$signature"
    printf 'pcr:%s' "$pcr_list" > "$pcr"
    ;;
  tpm2_checkquote)
    qualification=
    message=
    signature=
    pcr=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -q)
          qualification="$2"
          shift 2
          ;;
        -m)
          message="$2"
          shift 2
          ;;
        -s)
          signature="$2"
          shift 2
          ;;
        -f)
          pcr="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    qualification_hex=$(to_hex "$qualification")
    pcr_spec=$(cut -d: -f2- "$pcr" 2>/dev/null || true)
    if [ -z "$pcr_spec" ]; then
      pcr_spec=$(cut -d: -f2- < "$pcr")
    fi
    expected_message="quote:$pcr_spec:$qualification_hex"
    expected_signature="sig:$pcr_spec:$qualification_hex"
    [ "$(cat "$message")" = "$expected_message" ] || exit 1
    [ "$(cat "$signature")" = "$expected_signature" ] || exit 1
    ;;
  tpm2_createprimary)
    context=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -c)
          context="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    printf 'primary' > "$context"
    ;;
  tpm2_create)
    public=
    private=
    input=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -u)
          public="$2"
          shift 2
          ;;
        -r)
          private="$2"
          shift 2
          ;;
        -i)
          input="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    printf 'public' > "$public"
    cat "$input" > "$private"
    ;;
  tpm2_load)
    private=
    context=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -r)
          private="$2"
          shift 2
          ;;
        -c)
          context="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    cat "$private" > "$context"
    ;;
  tpm2_unseal)
    context=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -c)
          context="$2"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    cat "$context"
    ;;
  tpm2_flushcontext)
    exit 0
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
        detect_linux_tpm_runtime, generate_attestation_quote,
        load_or_initialize_master_key_from_tpm, load_or_initialize_rollback_floor_from_tpm,
        persist_rollback_floor_to_tpm, verify_attestation_quote, TestTpmHarness,
    };
    use crate::config::SecurityConfig;
    use std::{env, fs};

    #[test]
    fn detect_runtime_respects_explicit_tool_dir_and_device_override() {
        let harness = TestTpmHarness::install("detect-runtime");
        let security = SecurityConfig {
            linux_tpm_tools_dir: Some(harness.tools_dir),
            linux_tpm_device_path: Some(harness.device_path),
            linux_tpm_attestation_ak_path: Some(env::temp_dir().join("aegis-attestation-ak")),
            linux_tpm_attestation_pcrs: Some("sha256:0,7".to_string()),
            linux_tpm_master_key_nv_index: Some("0x1500016".to_string()),
            linux_tpm_rollback_nv_index: Some("0x1500017".to_string()),
            ..SecurityConfig::default()
        };

        let runtime = detect_linux_tpm_runtime(&security);
        assert!(runtime.available());
        assert!(runtime.attestation_enabled());
        assert!(runtime.master_key_enabled());
        assert!(runtime.rollback_enabled());
    }

    #[test]
    fn attestation_quote_round_trips_through_tpm_quote() {
        let harness = TestTpmHarness::install("attestation-quote");
        let security = SecurityConfig {
            linux_tpm_tools_dir: Some(harness.tools_dir),
            linux_tpm_device_path: Some(harness.device_path),
            linux_tpm_attestation_ak_path: Some(
                env::temp_dir().join("aegis-attestation-quote/attestation-ak"),
            ),
            linux_tpm_attestation_pcrs: Some("sha256:0,7".to_string()),
            ..SecurityConfig::default()
        };

        let quote = generate_attestation_quote(&security, b"quote-nonce").expect("generate quote");
        assert_eq!(quote.pcrs, "sha256:0,7");
        verify_attestation_quote(&security, &quote).expect("verify quote");
    }

    #[test]
    fn attestation_runtime_reports_missing_quote_tools() {
        let harness = TestTpmHarness::install("attestation-missing-tools");
        fs::remove_file(harness.tools_dir.join("tpm2_quote")).expect("remove quote tool");
        let security = SecurityConfig {
            linux_tpm_tools_dir: Some(harness.tools_dir),
            linux_tpm_device_path: Some(harness.device_path),
            linux_tpm_attestation_ak_path: Some(
                env::temp_dir().join("aegis-attestation-missing-tools/attestation-ak"),
            ),
            linux_tpm_attestation_pcrs: Some("sha256:0,7".to_string()),
            ..SecurityConfig::default()
        };

        let runtime = detect_linux_tpm_runtime(&security);
        assert!(!runtime.attestation_enabled());
        assert_eq!(
            runtime.attestation_status_error().as_deref(),
            Some("linux tpm attestation is configured but quote tools or device are unavailable")
        );
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
    fn master_key_round_trips_through_tpm_sealed_object() {
        let harness = TestTpmHarness::install("master-key-sealed");
        let sealed_root = env::temp_dir().join("aegis-master-key-sealed");
        let security = SecurityConfig {
            linux_tpm_tools_dir: Some(harness.tools_dir),
            linux_tpm_device_path: Some(harness.device_path),
            linux_tpm_master_key_sealed_object_path: Some(sealed_root.join("master-key")),
            ..SecurityConfig::default()
        };

        let first =
            load_or_initialize_master_key_from_tpm(&security).expect("provision sealed master key");
        let second =
            load_or_initialize_master_key_from_tpm(&security).expect("reload sealed master key");

        assert_eq!(first.len(), 32);
        assert_eq!(first, second);
    }

    #[test]
    fn master_key_falls_back_to_nv_index_when_sealed_tools_are_missing() {
        let harness = TestTpmHarness::install("master-key-fallback");
        for tool in [
            "tpm2_createprimary",
            "tpm2_create",
            "tpm2_load",
            "tpm2_unseal",
        ] {
            fs::remove_file(harness.tools_dir.join(tool)).expect("remove sealed tool");
        }
        let security = SecurityConfig {
            linux_tpm_tools_dir: Some(harness.tools_dir),
            linux_tpm_device_path: Some(harness.device_path),
            linux_tpm_master_key_sealed_object_path: Some(
                env::temp_dir().join("aegis-master-key-fallback/master-key"),
            ),
            linux_tpm_master_key_nv_index: Some("0x150001a".to_string()),
            linux_tpm_auto_provision_nv: true,
            ..SecurityConfig::default()
        };

        let first =
            load_or_initialize_master_key_from_tpm(&security).expect("provision fallback key");
        let second =
            load_or_initialize_master_key_from_tpm(&security).expect("reload fallback key");

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
