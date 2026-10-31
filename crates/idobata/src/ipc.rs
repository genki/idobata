use crate::{
    error::{INVALID, NETWORK, Result},
    types::{Config, Reply, Request},
};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Semaphore, mpsc, oneshot},
    time::{Duration, timeout},
};
pub struct Command {
    pub owner: String,
    pub request: Request,
    pub response: oneshot::Sender<Reply>,
}
const MAX: usize = 65536;
async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let len = stream.read_u32().await.map_err(|_| NETWORK)? as usize;
    if len == 0 || len > MAX {
        return Err(INVALID);
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await.map_err(|_| NETWORK)?;
    Ok(bytes)
}
async fn write<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX {
        return Err(INVALID);
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| NETWORK)?;
    stream.write_all(bytes).await.map_err(|_| NETWORK)?;
    stream.flush().await.map_err(|_| NETWORK)
}
async fn serve_one<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    owner: String,
    tx: mpsc::Sender<Command>,
) {
    let operation = async {
        let bytes = read(&mut stream).await?;
        let reply = match serde_json::from_slice::<Request>(&bytes) {
            Ok(request) => {
                let (response, rx) = oneshot::channel();
                tx.send(Command {
                    owner,
                    request,
                    response,
                })
                .await
                .map_err(|_| NETWORK)?;
                rx.await.map_err(|_| NETWORK)?
            }
            Err(_) => Reply::new(30, serde_json::json!({"status":"invalid","enqueued":false})),
        };
        write(
            &mut stream,
            &serde_json::to_vec(&reply).map_err(|_| INVALID)?,
        )
        .await
    };
    let _: std::result::Result<Result<()>, _> = timeout(Duration::from_secs(10), operation).await;
}
#[cfg(unix)]
pub async fn serve(c: Config, tx: mpsc::Sender<Command>) -> Result<()> {
    use std::{
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        path::Path,
    };
    let path = Path::new(&c.endpoint);
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
            return Err(INVALID);
        }
        std::fs::remove_file(path).map_err(|_| NETWORK)?;
    }
    let listener = tokio::net::UnixListener::bind(path).map_err(|_| NETWORK)?;
    if let Some(group) = c.socket_group {
        use std::ffi::CString;
        let name = CString::new(c.endpoint.as_bytes()).map_err(|_| INVALID)?;
        if unsafe { libc::chown(name.as_ptr(), u32::MAX, group) } != 0 {
            return Err(INVALID);
        }
    }
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if c.client_uids.is_empty() {
            0o600
        } else {
            0o660
        }),
    )
    .map_err(|_| NETWORK)?;
    let limits = Arc::new(Semaphore::new(8));
    loop {
        let permit = limits.clone().acquire_owned().await.map_err(|_| NETWORK)?;
        let (stream, _) = listener.accept().await.map_err(|_| NETWORK)?;
        let creds = stream.peer_cred().map_err(|_| NETWORK)?;
        let uid = creds.uid();
        if uid != unsafe { libc::geteuid() } && !c.client_uids.contains(&uid) {
            continue;
        }
        let tx = tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_one(stream, format!("uid:{uid}"), tx).await;
        });
    }
}
#[cfg(windows)]
fn pipe(c: &Config, first: bool) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
    };
    let own = crate::util::current_sid()?;
    let extra = if let Some(sid) = &c.client_sid {
        if !sid.starts_with("S-1-")
            || !sid
                .bytes()
                .all(|b| b == b'S' || b == b'-' || b.is_ascii_digit())
        {
            return Err(INVALID);
        }
        format!("(A;;0x0012019B;;;{sid})")
    } else {
        String::new()
    };
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;GA;;;{own}){extra}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(NETWORK);
    }
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                &c.endpoint,
                &mut sa as *mut _ as *mut std::ffi::c_void,
            )
    };
    unsafe {
        LocalFree(descriptor);
    }
    result.map_err(|_| NETWORK)
}
#[cfg(windows)]
pub async fn serve(c: Config, tx: mpsc::Sender<Command>) -> Result<()> {
    let mut server = pipe(&c, true)?;
    let limits = Arc::new(Semaphore::new(8));
    loop {
        let permit = limits.clone().acquire_owned().await.map_err(|_| NETWORK)?;
        server.connect().await.map_err(|_| NETWORK)?;
        let next = pipe(&c, false)?;
        let active = std::mem::replace(&mut server, next);
        let tx = tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_one(active, "authorized-local-pipe".into(), tx).await;
        });
    }
}
pub async fn call(endpoint: &str, request: &Request) -> Result<Reply> {
    let operation = async {
        #[cfg(unix)]
        let mut stream = tokio::net::UnixStream::connect(endpoint)
            .await
            .map_err(|_| NETWORK)?;
        #[cfg(windows)]
        let mut stream = {
            let end = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                match open_pipe(endpoint) {
                    Ok(s) => break s,
                    Err(e) if e.raw_os_error() == Some(231) && std::time::Instant::now() < end => {
                        tokio::time::sleep(Duration::from_millis(50)).await
                    }
                    Err(_) => return Err(NETWORK),
                }
            }
        };
        write(
            &mut stream,
            &serde_json::to_vec(request).map_err(|_| INVALID)?,
        )
        .await?;
        let bytes = read(&mut stream).await?;
        serde_json::from_slice(&bytes).map_err(|_| INVALID)
    };
    timeout(Duration::from_secs(12), operation)
        .await
        .map_err(|_| NETWORK)?
}

#[cfg(windows)]
fn open_pipe(endpoint: &str) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Storage::FileSystem::{
            CreateFileW, FILE_CREATE_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        },
    };
    let name: Vec<u16> = endpoint.encode_utf16().chain(Some(0)).collect();
    // FILE_APPEND_DATA is also FILE_CREATE_PIPE_INSTANCE: do not grant/request it for a client.
    let access = (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !FILE_CREATE_PIPE_INSTANCE;
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    unsafe { tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(handle) }
}
