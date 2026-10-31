//! Native entrypoint for agents using the protected, shared idobata daemon.
//! Build independently of the workspace: rustc --edition=2024 -O agent-cli.rs.

use std::ffi::{OsStr, OsString};
use std::process::{Command, ExitCode};

#[cfg(any(windows, test))]
use std::{io::Read, path::Path};

#[cfg(any(windows, test))]
const MAX_ENDPOINT_BYTES: u64 = 4096;

/// Only options before `--` belong to the CLI. Values and all other arguments
/// remain opaque, including non-UTF-8 Unix arguments and Windows wide strings.
fn needs_shared_endpoint(args: &[OsString]) -> bool {
    if args.first().is_some_and(|arg| arg == "help") || args.is_empty() {
        return false;
    }
    for arg in args {
        if arg == "--" {
            break;
        }
        if let Some(arg) = arg.to_str() {
            if matches!(
                arg,
                "--home" | "--socket" | "-h" | "--help" | "-V" | "--version"
            ) || arg.starts_with("--home=")
                || arg.starts_with("--socket=")
            {
                return false;
            }
        }
    }
    true
}

fn forwarded_args(args: Vec<OsString>, endpoint: Option<OsString>) -> Vec<OsString> {
    let Some(endpoint) = endpoint else {
        return args;
    };
    let mut forwarded = Vec::with_capacity(args.len() + 2);
    forwarded.push(OsString::from("--socket"));
    forwarded.push(endpoint);
    forwarded.extend(args);
    forwarded
}

#[cfg(any(windows, test))]
fn endpoint_from_reader(reader: impl Read) -> Result<OsString, ()> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_ENDPOINT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_ENDPOINT_BYTES {
        return Err(());
    }
    let text = String::from_utf8(bytes).map_err(|_| ())?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(());
    }
    Ok(OsString::from(text))
}

#[cfg(any(windows, test))]
fn windows_install_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    // The agent entrypoint can live anywhere on PATH. Its installation remains
    // in the protected SDK directory even when the entrypoint is copied/linked.
    let installation = Path::new(r"C:\Program Files\idobata");
    (
        installation.join("idobata.exe"),
        installation.join("agent.socket"),
    )
}

fn sdk_command(binary: &OsStr, args: Vec<OsString>, endpoint: Option<OsString>) -> Command {
    let mut command = Command::new(binary);
    command.args(forwarded_args(args, endpoint));
    // Command's default inherited streams preserve stdin as opaque bytes.
    command
}

fn failure(message: &'static str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(30)
}

#[cfg(unix)]
fn run(args: Vec<OsString>) -> ExitCode {
    use std::os::unix::process::CommandExt;
    #[cfg(target_os = "macos")]
    const ENDPOINT: &str = "/Library/Caches/idobata-runtime/ipc.sock";
    #[cfg(not(target_os = "macos"))]
    const ENDPOINT: &str = "/run/idobata/ipc.sock";

    let endpoint = needs_shared_endpoint(&args).then(|| OsString::from(ENDPOINT));
    let _error = sdk_command(OsStr::new("/usr/local/lib/idobata/idobata"), args, endpoint).exec();
    failure("idobata: native client could not start")
}

#[cfg(windows)]
fn run(args: Vec<OsString>) -> ExitCode {
    let (binary, endpoint_file) = windows_install_paths();
    let endpoint = if needs_shared_endpoint(&args) {
        let Ok(file) = std::fs::File::open(endpoint_file) else {
            return failure("idobata: shared daemon endpoint is unavailable");
        };
        let Ok(endpoint) = endpoint_from_reader(file) else {
            return failure("idobata: shared daemon endpoint is invalid");
        };
        Some(endpoint)
    } else {
        None
    };
    match sdk_command(binary.as_os_str(), args, endpoint).status() {
        Ok(status) => {
            // Windows process exit codes are 32 bits. Preserve their full bits,
            // including native codes which std exposes through a signed i32.
            std::process::exit(status.code().unwrap_or(30));
        }
        Err(_) => failure("idobata: native client could not start"),
    }
}

fn main() -> ExitCode {
    run(std::env::args_os().skip(1).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn ordinary_commands_select_shared_endpoint() {
        assert!(needs_shared_endpoint(&args(&["doctor"])));
        assert!(needs_shared_endpoint(&args(&["search", "--query", "help"])));
        assert!(needs_shared_endpoint(&args(&[
            "search",
            "--query",
            "--homeish=elsewhere"
        ])));
    }

    #[test]
    fn explicit_selection_is_preserved() {
        for values in [
            vec!["--home", "個人の設定", "doctor"],
            vec!["doctor", "--home=個人の設定"],
            vec!["--socket", "socket with spaces", "doctor"],
            vec!["doctor", "--socket=socket with spaces"],
            vec!["--socket=", "doctor"],
        ] {
            let original = args(&values);
            assert!(!needs_shared_endpoint(&original));
            assert_eq!(forwarded_args(original.clone(), None), original);
        }
    }

    #[test]
    fn terminator_and_opaque_arguments_are_preserved() {
        let original = args(&[
            "search",
            "--",
            "--socket=literal",
            "日本語 🐾",
            "\"quoted\"",
            "$(opaque)",
        ]);
        assert!(needs_shared_endpoint(&original));
        let actual = forwarded_args(original.clone(), Some(OsString::from("shared socket")));
        assert_eq!(&actual[..2], &args(&["--socket", "shared socket"]));
        assert_eq!(&actual[2..], &original);
    }

    #[test]
    fn help_and_version_need_no_endpoint_file() {
        for values in [
            vec![],
            vec!["--help"],
            vec!["-h"],
            vec!["--version"],
            vec!["-V"],
            vec!["help", "search"],
            vec!["public", "--help"],
        ] {
            assert!(!needs_shared_endpoint(&args(&values)));
        }
        assert!(needs_shared_endpoint(&args(&["search", "--", "--help"])));
    }

    #[test]
    fn bounded_endpoint_text_is_validated() {
        let pipe = r"\\.\pipe\idobata-共有";
        for suffix in ["", "\n", "\r\n"] {
            assert_eq!(
                endpoint_from_reader(format!("{pipe}{suffix}").as_bytes()),
                Ok(OsString::from(pipe))
            );
        }
        for invalid in [
            vec![],
            b"\n".to_vec(),
            b"one\ntwo".to_vec(),
            b"one\0two".to_vec(),
            vec![0xff],
            vec![b'a'; MAX_ENDPOINT_BYTES as usize + 1],
        ] {
            assert!(endpoint_from_reader(invalid.as_slice()).is_err());
        }
        assert!(endpoint_from_reader(vec![b'a'; MAX_ENDPOINT_BYTES as usize].as_slice()).is_ok());
    }

    #[test]
    fn windows_sdk_and_endpoint_use_protected_installation() {
        let paths = windows_install_paths();
        let installation = Path::new(r"C:\Program Files\idobata");
        assert_eq!(paths.0, installation.join("idobata.exe"));
        assert_eq!(paths.1, installation.join("agent.socket"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_unix_arguments_are_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let original = vec![
            OsString::from("doctor"),
            OsString::from_vec(vec![0xff, b' ', 0xfe]),
        ];
        assert!(needs_shared_endpoint(&original));
        let forwarded = forwarded_args(original.clone(), Some(OsString::from("socket")));
        assert_eq!(&forwarded[2..], &original);
    }

    #[test]
    fn native_command_preserves_arguments_stdin_streams_and_exit_code() {
        use std::io::Write;
        use std::process::Stdio;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "idobata launcher transport {} {unique}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("native-child.rs");
        let binary = root.join(format!("native-child{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(
            &source,
            r#"
use std::io::{Read, Write};
fn main() {
    let mut output = std::io::stdout();
    for arg in std::env::args_os().skip(1) {
        let arg = arg.into_string().unwrap();
        output.write_all(&(arg.len() as u32).to_le_bytes()).unwrap();
        output.write_all(arg.as_bytes()).unwrap();
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    output.write_all(&(input.len() as u32).to_le_bytes()).unwrap();
    output.write_all(&input).unwrap();
    output.flush().unwrap();
    std::io::stderr().write_all(b"native child stderr\n").unwrap();
    std::process::exit(47);
}
"#,
        )
        .unwrap();
        let compilation = Command::new("rustc")
            .arg("--edition=2024")
            .arg("--crate-name=idobata_launcher_test_child")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(compilation.status.success());

        let original = args(&[
            "post",
            "日本語 🐾",
            "two words",
            "",
            "\"quotes\" and 'apostrophes'",
            "C:\\trailing\\",
            "$(opaque); & | %PATH% !literal!",
            "--",
            "--socket=literal",
        ]);
        let expected_args = forwarded_args(original.clone(), Some(OsString::from("shared socket")));
        let mut child = sdk_command(
            binary.as_os_str(),
            original,
            Some(OsString::from("shared socket")),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        let input = b"\x00\xffopaque stdin\r\n$(); & | %PATH%";
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(47));
        assert_eq!(output.stderr, b"native child stderr\n");
        let mut expected = Vec::new();
        for arg in expected_args {
            let arg = arg.into_string().unwrap();
            expected.extend_from_slice(&(arg.len() as u32).to_le_bytes());
            expected.extend_from_slice(arg.as_bytes());
        }
        expected.extend_from_slice(&(input.len() as u32).to_le_bytes());
        expected.extend_from_slice(input);
        assert_eq!(output.stdout, expected);
        std::fs::remove_dir_all(root).unwrap();
    }
}
