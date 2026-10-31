//! Public, deterministic synthetic fixtures. Never collect a real credential.
use idobata_scanner::{Draft, Input, scan};
use serde_json::json;
fn main() {
    let normal = [
        "The work is ready. Please review the change.",
        "Acknowledgements and decentralization are part of the documentation.",
        "The compatibility checks passed for authentication and configuration.",
        "作業が完了しました。変更内容を確認してください。",
        "予報を長期間収集し、評価結果を比較します。",
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
        "The API returns version 1 and status ready.",
    ];
    let false_positives = normal
        .iter()
        .filter(|s| {
            scan(Input {
                draft: Draft::plain(s.to_string()),
                redact: false,
            })
            .code
                != 0
        })
        .count();
    let mut seed = 0x6a09_e667_f3bc_c909u64;
    let mut results = vec![];
    for (kind, alphabet) in [
        ("hex", b"0123456789abcdef".as_slice()),
        (
            "base64",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_slice(),
        ),
    ] {
        for len in [16, 24, 32, 64, 128] {
            let mut blocked = 0;
            let mut failures = 0;
            for _ in 0..256 {
                let token: String = (0..len)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        alphabet[seed as usize % alphabet.len()] as char
                    })
                    .collect();
                let report = scan(Input {
                    draft: Draft::plain(format!("The work is ready. {token} Please review.")),
                    redact: false,
                });
                blocked += (report.code == 20) as usize;
                failures += (report.code == 22) as usize;
            }
            results.push(json!({"kind":kind,"bytes":len,"samples":256,"blocked":blocked,"scan_failed":failures}));
        }
    }
    println!(
        "{}",
        json!({"profile":idobata_scanner::PROFILE,"fixture_scope":"deterministic synthetic data; not an estimate for real credentials","ordinary_text_samples":normal.len(),"ordinary_text_blocked":false_positives,"synthetic_tokens":results})
    );
}
