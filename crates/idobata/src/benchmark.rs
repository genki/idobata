//! 公開可能な合成corpusだけを用いる。ホストの入力・秘密値を収集しない。
use crate::{error::Result, scanner::Scanner, types::Draft, util};
use serde_json::json;
use std::{path::Path, time::Instant};

pub fn run(output: &Path) -> Result<serde_json::Value> {
    let phrases = [
        "作業が完了しました。変更を確認してください。",
        "予報を長期間収集し、評価結果を比較します。",
        "The work is ready. Please review the change.",
        "The API returns the status of each delivery.",
        "作业已完成，请检查更改。",
        "작업이 완료되었습니다. 변경 내용을 확인해 주세요.",
        "Работа готова. Проверьте изменения.",
        "El trabajo está listo. Revisa los cambios.",
        "Le travail est prêt. Vérifiez les modifications.",
        "Die Arbeit ist fertig. Bitte prüfe die Änderungen.",
        "العمل جاهز. يرجى مراجعة التغييرات.",
        "कार्य पूरा हो गया है। कृपया परिवर्तनों की समीक्षा करें।",
        "งานพร้อมแล้ว โปรดตรวจสอบการเปลี่ยนแปลง",
        "https://example.org/docs/overview",
        "fn main() { let ready = true; println!(\"ready\"); }",
        "The sender waits for a signed acknowledgement.",
    ];
    let mut cases = vec![];
    for i in 0..1024 {
        cases.push((
            "ordinary",
            format!(
                "{} {} {}",
                phrases[i % phrases.len()],
                i + 1,
                phrases[(i / phrases.len() + 3) % phrases.len()]
            ),
        ));
    }
    let mut seed = 0x6a09_e667_f3bc_c909u64;
    for i in 0..1280 {
        let alphabet = if i % 2 == 0 {
            b"0123456789abcdef".as_slice()
        } else {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_slice()
        };
        let len = [16, 24, 32, 64, 128][(i / 2) % 5];
        let token: String = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                alphabet[seed as usize % alphabet.len()] as char
            })
            .collect();
        let text = match (i / 10) % 4 {
            0 => token,
            1 => token.bytes().map(|b| format!("%{b:02X}")).collect(),
            2 => format!("The work is ready. {token} Please review."),
            _ => token.bytes().map(|b| format!("&#{};", b)).collect(),
        };
        cases.push((
            if i % 2 == 0 {
                "synthetic_hex"
            } else {
                "synthetic_base64"
            },
            text,
        ));
    }
    let scanner = Scanner::new()?;
    let mut decisions = vec![];
    let mut timing = vec![];
    let mut groups: std::collections::BTreeMap<&str, (usize, usize, usize)> = Default::default();
    let corpus_digest = util::hash(&util::canonical(&cases)?);
    for (index, (kind, body)) in cases.iter().enumerate() {
        let start = Instant::now();
        let report = scanner.scan(&Draft::plain(body.clone()), false)?;
        timing.push(start.elapsed().as_micros() as u64);
        let stats = groups.entry(kind).or_default();
        stats.0 += 1;
        stats.1 += (report.code == 20) as usize;
        stats.2 += (report.code != 0 && report.code != 20) as usize;
        decisions.push(json!({"case":index,"code":report.code,"findings":report.findings,"more_findings":report.more_findings}));
    }
    timing.sort_unstable();
    let value = json!({"version":1,"profile":Scanner::policy_id(),"wasm_sha256":Scanner::profile()["wasm_sha256"],
        "corpus_sha256":corpus_digest,"decision_sha256":util::hash(&util::canonical(&decisions)?),
        "scope":"authored template-expanded multilingual prose and deterministic synthetic tokens; not real credential prevalence",
        "license":"CC0-1.0 authored synthetic fixtures","os":std::env::consts::OS,"arch":std::env::consts::ARCH,
        "cases":cases.len(),"groups":groups.into_iter().map(|(k,(count,blocked,failed))|(k,json!({"count":count,"blocked":blocked,"failed":failed}))).collect::<std::collections::BTreeMap<_,_>>(),
        "latency_us":{"p50":timing[timing.len()/2],"p95":timing[timing.len()*95/100]},"decisions":decisions});
    util::atomic_write(output, &util::canonical(&value)?)?;
    Ok(
        json!({"status":"measured","cases":cases.len(),"corpus_sha256":value["corpus_sha256"],"decision_sha256":value["decision_sha256"],"latency_us":value["latency_us"],"groups":value["groups"]}),
    )
}
