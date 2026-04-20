#![cfg_attr(not(windows), allow(dead_code))]

use crate::config::{AgentConfig, SecurityConfig};
use anyhow::{bail, Context, Result};
#[cfg(windows)]
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
#[cfg(windows)]
use base64::Engine as _;
use getrandom::fill as getrandom_fill;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

#[cfg(windows)]
use anyhow::anyhow;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WindowsTpmRuntime {
    present: bool,
    ready: bool,
    last_error: Option<String>,
}

impl WindowsTpmRuntime {
    pub(crate) fn available(&self) -> bool {
        self.present && self.ready
    }

    pub(crate) fn last_error(&self) -> Option<String> {
        self.last_error.clone()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[cfg(windows)]
struct WindowsTpmProbe {
    present: bool,
    ready: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WindowsDpapiBlob {
    machine_scope: bool,
    purpose: String,
    ciphertext_b64: String,
}

pub(crate) fn detect_windows_tpm_runtime(_security: &SecurityConfig) -> WindowsTpmRuntime {
    #[cfg(windows)]
    {
        match probe_windows_tpm_runtime() {
            Ok(runtime) => runtime,
            Err(error) => WindowsTpmRuntime {
                present: false,
                ready: false,
                last_error: Some(format!("windows tpm detection failed: {error}")),
            },
        }
    }

    #[cfg(not(windows))]
    {
        if _security.windows_tpm_required {
            WindowsTpmRuntime {
                present: false,
                ready: false,
                last_error: Some("windows tpm provider requires Windows runtime".to_string()),
            }
        } else {
            WindowsTpmRuntime::default()
        }
    }
}

pub(crate) fn windows_dpapi_provider_detail(security: &SecurityConfig) -> String {
    let scope = if security.windows_dpapi_machine_scope {
        "machine-scope"
    } else {
        "user-scope"
    };
    format!("windows-dpapi:{scope}+install-hash-entropy")
}

pub(crate) fn load_or_initialize_master_key_from_windows_dpapi(
    config: &AgentConfig,
) -> Result<Vec<u8>> {
    let path = windows_master_key_blob_path(&config.storage.state_root);
    if path.exists() {
        let plaintext = decrypt_dpapi_blob(
            &path,
            &windows_dpapi_entropy_root(&config.storage.state_root),
            &config.security,
        )?;
        if plaintext.len() != 32 {
            bail!(
                "unexpected windows dpapi master key length {}, expected 32",
                plaintext.len()
            );
        }
        return Ok(plaintext);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create windows dpapi master key dir {}", parent.display()))?;
    }

    let mut secret = vec![0u8; 32];
    getrandom_fill(&mut secret)
        .map_err(|error| anyhow::anyhow!("generate windows dpapi master key bytes: {error}"))?;
    encrypt_dpapi_blob(
        &path,
        &secret,
        &windows_dpapi_entropy_root(&config.storage.state_root),
        &config.security,
        "master-key",
    )?;
    Ok(secret)
}

pub(crate) fn load_or_initialize_windows_dpapi_json<T>(
    binding_path: &Path,
    default_value: &T,
    security: &SecurityConfig,
    purpose: &str,
) -> Result<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    let path = windows_dpapi_json_path(binding_path, purpose);
    if path.exists() {
        let plaintext = decrypt_dpapi_blob(
            &path,
            &windows_dpapi_entropy_root_for(binding_path),
            security,
        )?;
        return serde_json::from_slice(&plaintext)
            .with_context(|| format!("parse windows dpapi json payload {}", path.display()));
    }

    persist_windows_dpapi_json(binding_path, default_value, security, purpose)?;
    Ok(default_value.clone())
}

pub(crate) fn persist_windows_dpapi_json<T>(
    binding_path: &Path,
    value: &T,
    security: &SecurityConfig,
    purpose: &str,
) -> Result<()>
where
    T: Serialize,
{
    let path = windows_dpapi_json_path(binding_path, purpose);
    let plaintext = serde_json::to_vec(value)
        .with_context(|| format!("serialize windows dpapi json payload for {purpose}"))?;
    encrypt_dpapi_blob(
        &path,
        &plaintext,
        &windows_dpapi_entropy_root_for(binding_path),
        security,
        purpose,
    )
}

#[cfg(windows)]
fn probe_windows_tpm_runtime() -> Result<WindowsTpmRuntime> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$tpm = Get-Tpm -ErrorAction Stop; [ordered]@{ present = [bool]$tpm.TpmPresent; ready = [bool]$tpm.TpmReady } | ConvertTo-Json -Compress",
        ])
        .output()
        .context("run Get-Tpm probe")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "Get-Tpm probe failed with status {}: {}",
            output.status,
            stderr
        );
    }

    let probe: WindowsTpmProbe =
        serde_json::from_slice(&output.stdout).context("parse Get-Tpm probe json output")?;
    Ok(WindowsTpmRuntime {
        present: probe.present,
        ready: probe.ready,
        last_error: None,
    })
}

fn windows_master_key_blob_path(state_root: &Path) -> PathBuf {
    state_root.join("secure").join("master-key.dpapi.json")
}

fn windows_dpapi_json_path(binding_path: &Path, purpose: &str) -> PathBuf {
    binding_path.with_extension(format!("{purpose}.dpapi.json"))
}

fn windows_dpapi_entropy_root_for(binding_path: &Path) -> PathBuf {
    binding_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn windows_dpapi_entropy_root(state_root: &Path) -> PathBuf {
    state_root.to_path_buf()
}

fn windows_dpapi_entropy_path(root: &Path) -> PathBuf {
    root.join("secure").join("dpapi-entropy.bin")
}

fn load_or_initialize_windows_dpapi_entropy(root: &Path) -> Result<Vec<u8>> {
    let path = windows_dpapi_entropy_path(root);
    if path.exists() {
        let entropy = fs::read(&path)
            .with_context(|| format!("read windows dpapi entropy {}", path.display()))?;
        if entropy.len() != 32 {
            bail!(
                "unexpected windows dpapi entropy length {}, expected 32",
                entropy.len()
            );
        }
        return Ok(entropy);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create windows dpapi entropy dir {}", parent.display()))?;
    }

    let exe_path =
        std::env::current_exe().context("locate current executable for dpapi entropy")?;
    let binary = fs::read(&exe_path)
        .with_context(|| format!("read current executable {}", exe_path.display()))?;
    let entropy = blake3::hash(&binary).as_bytes().to_vec();

    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(&entropy)
                .with_context(|| format!("write windows dpapi entropy {}", path.display()))?;
            restrict_owner_only(&path)?;
            Ok(entropy)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let entropy = fs::read(&path)
                .with_context(|| format!("reload windows dpapi entropy {}", path.display()))?;
            if entropy.len() != 32 {
                bail!(
                    "unexpected windows dpapi entropy length {}, expected 32",
                    entropy.len()
                );
            }
            Ok(entropy)
        }
        Err(error) => Err(error.into()),
    }
}

fn encrypt_dpapi_blob(
    path: &Path,
    plaintext: &[u8],
    entropy_root: &Path,
    security: &SecurityConfig,
    purpose: &str,
) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = (path, plaintext, entropy_root, security, purpose);
        bail!("windows dpapi provider requires Windows runtime");
    }

    #[cfg(windows)]
    {
        let entropy = load_or_initialize_windows_dpapi_entropy(entropy_root)?;
        let ciphertext = dpapi_protect(
            plaintext,
            &entropy,
            security.windows_dpapi_machine_scope,
            purpose,
        )?;
        let blob = WindowsDpapiBlob {
            machine_scope: security.windows_dpapi_machine_scope,
            purpose: purpose.to_string(),
            ciphertext_b64: BASE64_STANDARD.encode(ciphertext),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create windows dpapi blob dir {}", parent.display()))?;
        }
        fs::write(path, serde_json::to_vec_pretty(&blob)?)
            .with_context(|| format!("write windows dpapi blob {}", path.display()))?;
        restrict_owner_only(path)?;
        Ok(())
    }
}

fn decrypt_dpapi_blob(
    path: &Path,
    entropy_root: &Path,
    security: &SecurityConfig,
) -> Result<Vec<u8>> {
    #[cfg(not(windows))]
    {
        let _ = (path, entropy_root, security);
        bail!("windows dpapi provider requires Windows runtime");
    }

    #[cfg(windows)]
    {
        let blob: WindowsDpapiBlob = serde_json::from_slice(
            &fs::read(path)
                .with_context(|| format!("read windows dpapi blob {}", path.display()))?,
        )
        .with_context(|| format!("parse windows dpapi blob {}", path.display()))?;

        if blob.machine_scope != security.windows_dpapi_machine_scope {
            bail!(
                "windows dpapi blob scope mismatch for {}: expected machine_scope={}, got {}",
                path.display(),
                security.windows_dpapi_machine_scope,
                blob.machine_scope
            );
        }

        let entropy = load_or_initialize_windows_dpapi_entropy(entropy_root)?;
        let ciphertext = BASE64_STANDARD
            .decode(&blob.ciphertext_b64)
            .with_context(|| format!("decode windows dpapi ciphertext {}", path.display()))?;
        dpapi_unprotect(&ciphertext, &entropy)
    }
}

#[cfg(windows)]
fn dpapi_protect(
    plaintext: &[u8],
    entropy: &[u8],
    machine_scope: bool,
    purpose: &str,
) -> Result<Vec<u8>> {
    let mut input_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut entropy_bytes = entropy.to_vec();
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let description: Vec<u16> = purpose.encode_utf16().chain(std::iter::once(0)).collect();
    let flags = CRYPTPROTECT_UI_FORBIDDEN
        | if machine_scope {
            CRYPTPROTECT_LOCAL_MACHINE
        } else {
            0
        };

    let ok = unsafe {
        CryptProtectData(
            &mut input_blob,
            description.as_ptr(),
            &mut entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            flags,
            &mut output_blob,
        )
    };
    if ok == 0 {
        return Err(anyhow!(
            "CryptProtectData failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let ciphertext = unsafe {
        std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec()
    };
    unsafe {
        LocalFree(output_blob.pbData.cast());
    }
    Ok(ciphertext)
}

#[cfg(windows)]
fn dpapi_unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    let mut input_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut entropy_bytes = entropy.to_vec();
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy_bytes.len() as u32,
        pbData: entropy_bytes.as_mut_ptr(),
    };
    let mut output_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let mut description_ptr = std::ptr::null_mut();

    let ok = unsafe {
        CryptUnprotectData(
            &mut input_blob,
            &mut description_ptr,
            &mut entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output_blob,
        )
    };
    if ok == 0 {
        return Err(anyhow!(
            "CryptUnprotectData failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let plaintext = unsafe {
        std::slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec()
    };
    unsafe {
        if !description_ptr.is_null() {
            LocalFree(description_ptr.cast());
        }
        LocalFree(output_blob.pbData.cast());
    }
    Ok(plaintext)
}

#[cfg(unix)]
fn restrict_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{detect_windows_tpm_runtime, windows_dpapi_provider_detail};
    use crate::config::SecurityConfig;

    #[test]
    fn windows_dpapi_provider_detail_reflects_scope() {
        let mut security = SecurityConfig::default();
        security.windows_dpapi_machine_scope = true;
        assert_eq!(
            windows_dpapi_provider_detail(&security),
            "windows-dpapi:machine-scope+install-hash-entropy"
        );

        security.windows_dpapi_machine_scope = false;
        assert_eq!(
            windows_dpapi_provider_detail(&security),
            "windows-dpapi:user-scope+install-hash-entropy"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_tpm_runtime_reports_non_windows_requirement_when_configured() {
        let mut security = SecurityConfig::default();
        security.windows_tpm_required = true;

        let runtime = detect_windows_tpm_runtime(&security);
        assert!(!runtime.available());
        assert_eq!(
            runtime.last_error().as_deref(),
            Some("windows tpm provider requires Windows runtime")
        );
    }
}
