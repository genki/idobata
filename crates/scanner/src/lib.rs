//! Deterministic, bounded content inspection. No host input, filesystem, network or clock.
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

pub const PROFILE: &str = "strict-v1.0.0";
pub const SCALE: u64 = 1 << 20;
pub const MAX_BODY: usize = 8192;
pub const MAX_EXPANDED: usize = 262144;
pub const MAX_CANDIDATES: usize = 128;
pub const MAX_FINDINGS: usize = 32;
const WINDOWS: [usize; 4] = [16, 32, 64, 128];
// Q20 bit/byte thresholds. Frozen profile, deliberately no language identification.
const HEX: [u64; 4] = [3_407_872, 3_774_874, 3_879_731, 3_984_589]; // 3.25,3.6,3.7,3.8
const B64: [u64; 4] = [3_932_160, 4_718_592, 5_138_022, 5_347_738]; // 3.75,4.5,4.9,5.1
const OTHER: [u64; 4] = [4_194_304, 4_928_307, 5_557_453, 6_081_741]; // 4,4.7,5.3,5.8

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default = "default_title")]
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub references: Vec<String>,
}
fn default_kind() -> String {
    "observation".into()
}
fn default_title() -> String {
    "Observation".into()
}
impl Draft {
    pub fn plain(body: String) -> Self {
        Self {
            kind: default_kind(),
            title: default_title(),
            body,
            references: vec![],
        }
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub field: String,
    pub rule: String,
    pub start_byte: usize,
    pub end_byte: usize,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub status: String,
    pub code: i32,
    pub profile: String,
    pub findings: Vec<Finding>,
    pub more_findings: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted: Option<Draft>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub draft: Draft,
    pub redact: bool,
}

/// floor(log2(n) * 2^20), using only portable unsigned integer arithmetic.
pub const fn log2_q20(n: usize) -> u64 {
    if n == 0 {
        return 0;
    }
    let exponent = 63 - (n as u64).leading_zeros() as u64;
    let mut x = (n as u64) << (31 - exponent);
    let mut value = exponent << 20;
    let mut bit = 0;
    while bit < 20 {
        x = ((x as u128 * x as u128) >> 31) as u64;
        if x >= (1u64 << 32) {
            x >>= 1;
            value |= 1 << (19 - bit);
        }
        bit += 1;
    }
    value
}
const fn logs() -> [u64; 129] {
    let mut table = [0; 129];
    let mut i = 1;
    while i < 129 {
        table[i] = log2_q20(i);
        i += 1;
    }
    table
}
pub const LOGS: [u64; 129] = logs();
fn contribution(count: usize) -> u64 {
    count as u64 * LOGS[count]
}
fn b64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"+/_-=".contains(&b)
}
fn inspect_bytes(bytes: &[u8], output: &mut Vec<(usize, usize)>) {
    let utf8_text = std::str::from_utf8(bytes).is_ok();
    for (wi, size) in WINDOWS.into_iter().enumerate() {
        if bytes.len() < size {
            continue;
        }
        let mut counts = [0usize; 256];
        let mut sum = 0;
        let mut hex_count = 0usize;
        let mut b64_count = 0usize;
        for b in &bytes[..size] {
            let c = &mut counts[*b as usize];
            sum -= contribution(*c);
            *c += 1;
            sum += contribution(*c);
            hex_count += b.is_ascii_hexdigit() as usize;
            b64_count += b64_char(*b) as usize;
        }
        for start in 0..=bytes.len() - size {
            let entropy = LOGS[size] - sum / size as u64;
            if (entropy >= OTHER[wi]
                && (wi >= 2
                    || !utf8_text
                    || bytes[start..start + size]
                        .iter()
                        .all(|b| b.is_ascii() && !b.is_ascii_whitespace())))
                || (hex_count == size && entropy >= HEX[wi])
                || (b64_count == size && entropy >= B64[wi])
            {
                // Keep a union rather than an unbounded finding per overlapping window.
                if let Some(last) = output.last_mut().filter(|r| r.0 <= start && start <= r.1) {
                    last.1 = last.1.max(start + size);
                } else {
                    output.push((start, start + size));
                }
            }
            if start + size < bytes.len() {
                let old = bytes[start];
                let new = bytes[start + size];
                let c = &mut counts[old as usize];
                sum -= contribution(*c);
                *c -= 1;
                sum += contribution(*c);
                let c = &mut counts[new as usize];
                sum -= contribution(*c);
                *c += 1;
                sum += contribution(*c);
                hex_count =
                    hex_count - old.is_ascii_hexdigit() as usize + new.is_ascii_hexdigit() as usize;
                b64_count = b64_count - b64_char(old) as usize + b64_char(new) as usize;
            }
        }
    }
}
fn union(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = vec![];
    for (a, b) in spans {
        if let Some(last) = merged.last_mut().filter(|r| a <= r.1) {
            last.1 = last.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    merged
}
fn percent_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut changed = false;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16).map(|x| x as u8);
            if let (Some(a), Some(b)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(a * 16 + b);
                i += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    changed.then_some(out)
}
fn json_unescape(text: &str) -> Option<Vec<u8>> {
    if !text.contains('\\') {
        return None;
    }
    // Preserve raw quotes; interpret only complete JSON escapes in text.
    let bytes = text.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    let mut changed = false;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let len = if bytes[i + 1] == b'u' {
                if i + 6 <= bytes.len() { 6 } else { 0 }
            } else if b"\"\\/bfnrt".contains(&bytes[i + 1]) {
                2
            } else {
                0
            };
            if len > 0 {
                let mut end = i + len;
                if len == 6 && end + 6 <= bytes.len() && &bytes[end..end + 2] == b"\\u" {
                    end += 6;
                }
                let Some(fragment) = text.get(i..end) else {
                    out.push(bytes[i]);
                    i += 1;
                    continue;
                };
                let quoted = format!("\"{}\"", fragment);
                if let Ok(decoded) = serde_json::from_str::<String>(&quoted) {
                    out.extend(decoded.as_bytes());
                    i = end;
                    changed = true;
                    continue;
                }
                if len == 6 && end > i + 6 {
                    let Some(fragment) = text.get(i..i + 6) else {
                        out.push(bytes[i]);
                        i += 1;
                        continue;
                    };
                    let quoted = format!("\"{}\"", fragment);
                    if let Ok(decoded) = serde_json::from_str::<String>(&quoted) {
                        out.extend(decoded.as_bytes());
                        i += 6;
                        changed = true;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    changed.then_some(out)
}
struct Budget {
    bytes: usize,
    candidates: usize,
}
// Transformed views use the source span of the whole view when byte mapping is ambiguous.
fn inspect_view(
    bytes: &[u8],
    depth: usize,
    root: (usize, usize),
    exact: bool,
    budget: &mut Budget,
    spans: &mut Vec<(usize, usize)>,
) -> Result<(), ()> {
    budget.bytes = budget.bytes.checked_add(bytes.len()).ok_or(())?;
    budget.candidates += 1;
    if budget.bytes > MAX_EXPANDED || budget.candidates > MAX_CANDIDATES {
        return Err(());
    }
    let mut local = vec![];
    inspect_bytes(bytes, &mut local);
    for (a, b) in local {
        spans.push(if exact {
            (root.0 + a, root.0 + b)
        } else {
            root
        });
    }
    let mut views: Vec<(Vec<u8>, (usize, usize))> = vec![];
    if let Some(out) = percent_decode(bytes) {
        views.push((out, root));
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if contains_data_url(text) {
            return Err(());
        }
        let norm: String = text.nfkc().collect();
        if norm != text {
            views.push((norm.into_bytes(), root));
        }
        let html = html_escape::decode_html_entities(text);
        if html != text {
            views.push((html.into_owned().into_bytes(), root));
        }
        if let Some(out) = json_unescape(text) {
            views.push((out, root));
        }
        // Candidate boundaries depend on byte syntax, never on a language dictionary.
        let mut start = 0;
        while start < bytes.len() {
            if !b64_char(bytes[start]) {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < bytes.len() && b64_char(bytes[end]) {
                end += 1;
            }
            let token = &bytes[start..end];
            let span = if exact {
                (root.0 + start, root.0 + end)
            } else {
                root
            };
            if token.len() >= 32
                && token.len().is_multiple_of(2)
                && token.iter().all(u8::is_ascii_hexdigit)
            {
                let mut out = Vec::with_capacity(token.len() / 2);
                for pair in token.chunks_exact(2) {
                    out.push(
                        ((pair[0] as char).to_digit(16).unwrap() * 16
                            + (pair[1] as char).to_digit(16).unwrap())
                            as u8,
                    );
                }
                views.push((out, span));
            } else if token.len() >= 24
                && token
                    .iter()
                    .any(|b| b.is_ascii_digit() || b"+/_-=".contains(b))
            {
                let trimmed = token
                    .strip_suffix(b"==")
                    .or_else(|| token.strip_suffix(b"="))
                    .unwrap_or(token);
                for engine in [
                    &general_purpose::STANDARD_NO_PAD,
                    &general_purpose::URL_SAFE_NO_PAD,
                ] {
                    if let Ok(out) = engine.decode(trimmed) {
                        views.push((out, span));
                        break;
                    }
                }
            }
            if views.len() > MAX_CANDIDATES {
                return Err(());
            }
            start = end;
        }
    }
    for (view, span) in views {
        if view == bytes {
            continue;
        }
        if depth >= 3 {
            return Err(());
        }
        inspect_view(&view, depth + 1, span, false, budget, spans)?;
    }
    Ok(())
}
fn contains_data_url(text: &str) -> bool {
    text.as_bytes().windows(5).enumerate().any(|(i, w)| {
        w.eq_ignore_ascii_case(b"data:")
            && (i == 0
                || (!text.as_bytes()[i - 1].is_ascii_alphanumeric()
                    && text.as_bytes()[i - 1] != b'_'))
    })
}
fn valid_text(s: &str) -> bool {
    !s.chars().any(|c| {
        (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
            || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'|'\u{200b}'|'\u{feff}')
    })
}
fn redact_text(text: &str, spans: Vec<(usize, usize)>, reference: bool) -> String {
    let mut expanded = vec![];
    for (mut a, mut b) in spans {
        if reference {
            a = 0;
            b = text.len();
        }
        while a > 0 && !text.is_char_boundary(a) {
            a -= 1;
        }
        while b < text.len() && !text.is_char_boundary(b) {
            b += 1;
        }
        // Expand a detected substring inside a body URL to the entire URL token.
        let left = text[..a]
            .rfind(char::is_whitespace)
            .map(|i| i + 1)
            .unwrap_or(0);
        let right = text[b..]
            .find(char::is_whitespace)
            .map(|i| b + i)
            .unwrap_or(text.len());
        let token = &text[left..right];
        if token.starts_with("https://") || token.starts_with("http://") {
            a = left;
            b = right;
        }
        expanded.push((a, b));
    }
    let mut out = String::new();
    let mut last = 0;
    for (i, (a, b)) in union(expanded).into_iter().enumerate() {
        out.push_str(&text[last..a]);
        out.push_str(&format!("[REDACTED_{}]", i + 1));
        last = b;
    }
    out.push_str(&text[last..]);
    out
}
fn error(code: i32) -> Report {
    Report {
        status: if code == 30 { "invalid" } else { "scan_failed" }.into(),
        code,
        profile: PROFILE.into(),
        findings: vec![],
        more_findings: false,
        redacted: None,
    }
}
pub fn scan(input: Input) -> Report {
    let draft = &input.draft;
    if !["observation", "question", "answer", "proposal"].contains(&draft.kind.as_str())
        || draft.body.is_empty()
        || draft.body.len() > MAX_BODY
        || draft.title.is_empty()
        || draft.title.len() > 256
        || draft.references.len() > 4
        || draft.references.iter().any(|r| r.len() > 2048)
    {
        return error(30);
    }
    let mut fields = vec![
        ("title".to_string(), draft.title.as_str()),
        ("body".to_string(), draft.body.as_str()),
    ];
    for (i, r) in draft.references.iter().enumerate() {
        fields.push((format!("references[{i}]"), r));
    }
    let mut budget = Budget {
        bytes: 0,
        candidates: 0,
    };
    let mut findings = vec![];
    let mut redacted = draft.clone();
    for (field, text) in fields {
        if !valid_text(text) || contains_data_url(text) {
            return error(22);
        }
        let mut spans = vec![];
        if inspect_view(
            text.as_bytes(),
            0,
            (0, text.len()),
            true,
            &mut budget,
            &mut spans,
        )
        .is_err()
        {
            return error(22);
        }
        let spans = union(spans);
        for (a, b) in &spans {
            findings.push(Finding {
                field: field.clone(),
                rule: "high_entropy_substring".into(),
                start_byte: *a,
                end_byte: *b,
            });
        }
        if input.redact && !spans.is_empty() {
            let cleaned = redact_text(text, spans, field.starts_with("references"));
            if field == "title" {
                redacted.title = cleaned;
            } else if field == "body" {
                redacted.body = cleaned;
            } else {
                let i = field
                    .trim_start_matches("references[")
                    .trim_end_matches(']')
                    .parse::<usize>()
                    .unwrap();
                redacted.references[i] = cleaned;
            }
        }
    }
    let blocked = !findings.is_empty();
    let more = findings.len() > MAX_FINDINGS;
    findings.truncate(MAX_FINDINGS);
    Report {
        status: if blocked { "blocked" } else { "passed" }.into(),
        code: if blocked { 20 } else { 0 },
        profile: PROFILE.into(),
        findings,
        more_findings: more,
        redacted: input.redact.then_some(redacted),
    }
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn allocate(len: u32) -> u32 {
    let buffer = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(buffer) as *mut u8 as u32
}
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inspect(ptr: u32, len: u32) -> u64 {
    let input = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let report = match serde_json::from_slice::<Input>(input) {
        Ok(i) => scan(i),
        Err(_) => error(30),
    };
    let output = serde_json::to_vec(&report).unwrap().into_boxed_slice();
    let len = output.len();
    let ptr = Box::into_raw(output) as *mut u8 as u32;
    ((ptr as u64) << 32) | len as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn integer_logs() {
        assert_eq!(LOGS[1], 0);
        assert_eq!(LOGS[16], 4 * SCALE);
        assert_eq!(LOGS[128], 7 * SCALE);
    }
    #[test]
    fn block_token_without_echo() {
        let r = scan(Input {
            draft: Draft::plain("Hello 9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u".into()),
            redact: false,
        });
        assert_eq!(r.code, 20);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("9aK7"));
    }
    #[test]
    fn multilingual_prose() {
        for text in [
            "The build is ready. Please review the change.",
            "ビルドが完了しました。変更内容を確認してください。",
            "El trabajo está listo. Revisa los cambios.",
            "作业已完成，请检查更改。",
            "Работа готова. Проверьте изменения.",
        ] {
            assert_eq!(
                scan(Input {
                    draft: Draft::plain(text.into()),
                    redact: false
                })
                .code,
                0,
                "{text}"
            );
        }
    }
    #[test]
    fn reject_duplicate_keys() {
        assert!(
            serde_json::from_str::<Input>(r#"{"draft":{"body":"a","body":"b"},"redact":false}"#)
                .is_err()
        );
    }
    #[test]
    fn redaction_removes_original() {
        let s = "9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u";
        let r = scan(Input {
            draft: Draft::plain(format!("Hello {s}")),
            redact: true,
        });
        assert_eq!(r.code, 20);
        let d = r.redacted.unwrap();
        assert!(!d.body.contains(s));
        assert_eq!(
            scan(Input {
                draft: d,
                redact: false
            })
            .code,
            0
        );
    }
    #[test]
    fn bounded_decoding() {
        let text = "&#37;25".repeat(1200);
        assert!(matches!(
            scan(Input {
                draft: Draft::plain(text),
                redact: false
            })
            .code,
            22 | 30
        ));
    }
    #[test]
    fn normalized_and_encoded() {
        let token = "9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u";
        let hex = token
            .as_bytes()
            .iter()
            .map(|b| format!("%{b:02x}"))
            .collect::<String>();
        assert_eq!(
            scan(Input {
                draft: Draft::plain(hex),
                redact: false
            })
            .code,
            20
        );
    }
    #[test]
    fn control_input_fails_closed() {
        assert_eq!(
            scan(Input {
                draft: Draft::plain("safe\u{202e}text".into()),
                redact: false
            })
            .code,
            22
        );
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    #[test]
    fn unicode_escape_boundaries_never_panic() {
        for text in [
            r"\uあいう",
            r"\u日a\u0000",
            r"\ud800",
            r"\ud83d\ude00",
            r"\u1234\uあい",
            r"x\u日xx\u0000",
        ] {
            let _ = scan(Input {
                draft: Draft::plain(text.into()),
                redact: true,
            });
        }
    }
    #[test]
    fn padding_does_not_hide_a_block() {
        let token = "9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u";
        let long = format!("{} {token} {}", "a ".repeat(1000), "b ".repeat(1000));
        assert_eq!(
            scan(Input {
                draft: Draft::plain(long),
                redact: false
            })
            .code,
            20
        );
    }
    #[test]
    fn inspect_every_free_text_field() {
        for field in 0..3 {
            let mut d = Draft::plain("The work is ready.".into());
            let token = "9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u";
            match field {
                0 => d.title = token.into(),
                1 => d.body = token.into(),
                _ => d.references = vec![format!("https://example.org/?value={token}")],
            };
            assert_eq!(
                scan(Input {
                    draft: d,
                    redact: false
                })
                .code,
                20
            );
        }
    }
    #[test]
    fn transformed_content_keeps_source_offsets() {
        let token = "9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u";
        let encoded = token
            .chars()
            .map(|c| format!("&#{};", c as u32))
            .collect::<String>();
        let r = scan(Input {
            draft: Draft::plain(encoded.clone()),
            redact: true,
        });
        assert_eq!(r.code, 20);
        assert!(r.findings.iter().all(|f| f.end_byte <= encoded.len()));
        assert!(!r.redacted.unwrap().body.contains("&#"));
    }
}

#[cfg(test)]
mod text_window_tests {
    use super::*;
    #[test]
    fn short_utf8_windows_do_not_mistake_varied_prose_for_binary() {
        let r = scan(Input {
            draft: Draft::plain("予報を長期間収集し、評価結果を比較します。".into()),
            redact: false,
        });
        assert_eq!(r.code, 0);
    }
    #[test]
    fn metadata_word_is_not_a_data_url() {
        assert_eq!(
            scan(Input {
                draft: Draft::plain("metadata: status ready".into()),
                redact: false
            })
            .code,
            0
        );
        for body in ["data:text/plain,hello", "&#100;ata:text/plain,hello"] {
            assert_eq!(
                scan(Input {
                    draft: Draft::plain(body.into()),
                    redact: false
                })
                .code,
                22
            );
        }
    }
}
