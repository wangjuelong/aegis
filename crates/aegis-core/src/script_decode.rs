use base64::Engine;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeLayerKind {
    Base64,
    PowerShellEncodedCommand,
    CharCode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptDecodeStep {
    pub kind: DecodeLayerKind,
    pub output: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptDecodeReport {
    pub original: String,
    pub decoded: String,
    pub layers: Vec<ScriptDecodeStep>,
    pub suspicious_tokens: Vec<String>,
}

#[derive(Default)]
pub struct ScriptDecodePipeline;

impl ScriptDecodePipeline {
    pub fn decode(&self, input: &str) -> ScriptDecodeReport {
        let mut current = input.trim().to_string();
        let mut layers = Vec::new();

        for _ in 0..4 {
            let next = self.decode_once(&current);
            let Some((kind, decoded)) = next else {
                break;
            };
            if decoded == current {
                break;
            }
            layers.push(ScriptDecodeStep {
                kind,
                output: decoded.clone(),
            });
            current = decoded;
        }

        ScriptDecodeReport {
            original: input.to_string(),
            suspicious_tokens: suspicious_tokens(&current),
            decoded: current,
            layers,
        }
    }

    fn decode_once(&self, input: &str) -> Option<(DecodeLayerKind, String)> {
        decode_powershell(input)
            .map(|decoded| (DecodeLayerKind::PowerShellEncodedCommand, decoded))
            .or_else(|| decode_base64(input).map(|decoded| (DecodeLayerKind::Base64, decoded)))
            .or_else(|| decode_charcode(input).map(|decoded| (DecodeLayerKind::CharCode, decoded)))
    }
}

fn decode_base64(input: &str) -> Option<String> {
    let compact = input
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    if compact.len() < 8 || compact.len() % 4 != 0 {
        return None;
    }
    if !compact
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return None;
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn decode_powershell(input: &str) -> Option<String> {
    let normalized = input.trim();
    let marker = normalized
        .find("-enc ")
        .or_else(|| normalized.find("-EncodedCommand "))?;
    let encoded = normalized[marker..]
        .split_whitespace()
        .nth(1)?
        .trim_matches('"');
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .ok()?;
    if decoded.len() % 2 != 0 {
        return None;
    }

    let utf16 = decoded
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&utf16).ok()
}

fn decode_charcode(input: &str) -> Option<String> {
    let mut values = Vec::new();
    let normalized = input.trim();

    if let Some(args) = normalized
        .strip_prefix("String.fromCharCode(")
        .and_then(|value| value.strip_suffix(')'))
    {
        for value in args.split(',') {
            values.push(value.trim().parse::<u32>().ok()?);
        }
    } else if normalized.contains("chr(") {
        for fragment in normalized.split("chr(").skip(1) {
            let end = fragment.find(')')?;
            values.push(fragment[..end].trim().parse::<u32>().ok()?);
        }
    } else {
        return None;
    }

    let decoded = values
        .into_iter()
        .map(char::from_u32)
        .collect::<Option<String>>()?;
    (!decoded.is_empty()).then_some(decoded)
}

fn suspicious_tokens(content: &str) -> Vec<String> {
    const TOKENS: [&str; 6] = [
        "Invoke-Expression",
        "IEX",
        "AmsiUtils",
        "FromBase64String",
        "VirtualAlloc",
        "Invoke-Mimikatz",
    ];

    TOKENS
        .into_iter()
        .filter(|token| content.contains(token))
        .map(|token| token.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{DecodeLayerKind, ScriptDecodePipeline};
    use base64::Engine;

    #[test]
    fn decode_pipeline_decodes_powershell_encoded_command() {
        let utf16: Vec<u8> = "Invoke-Expression"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        let pipeline = ScriptDecodePipeline;

        let report = pipeline.decode(&format!("powershell -enc {encoded}"));

        assert_eq!(report.layers.len(), 1);
        assert_eq!(
            report.layers[0].kind,
            DecodeLayerKind::PowerShellEncodedCommand
        );
        assert_eq!(report.decoded, "Invoke-Expression");
    }

    #[test]
    fn decode_pipeline_decodes_charcode_sequences() {
        let pipeline = ScriptDecodePipeline;

        let report = pipeline.decode("String.fromCharCode(73,69,88)");

        assert_eq!(report.layers.len(), 1);
        assert_eq!(report.layers[0].kind, DecodeLayerKind::CharCode);
        assert_eq!(report.decoded, "IEX");
        assert_eq!(report.suspicious_tokens, vec!["IEX".to_string()]);
    }
}
