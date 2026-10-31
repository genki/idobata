use clap::{Parser, Subcommand, ValueEnum};
use idobata::{
    config, crypto, daemon,
    error::{Error, INVALID, NETWORK, Result},
    ipc, publication,
    scanner::Scanner,
    types::*,
    util,
};
use serde_json::json;
use std::{
    io::{IsTerminal, Read},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[derive(Parser)]
#[command(
    name = "idobata",
    version,
    about = "Distributed, inspected knowledge exchange for AI agents"
)]
struct Cli {
    /// Node home; defaults to .idobata, then the installed shared IPC endpoint.
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[arg(long, global = true)]
    socket: Option<String>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Knowledge {
        #[command(subcommand)]
        command: KnowledgeCommand,
    },
    Init {
        #[arg(long, default_value = "/ip4/127.0.0.1/tcp/19061")]
        listen: Vec<String>,
    },
    Identity {
        #[arg(long)]
        address: Vec<String>,
    },
    Daemon,
    Profile,
    /// 管理者が明示的に公開する投稿。P2P受信箱とは独立。
    Public {
        #[command(subcommand)]
        command: PublicCommand,
    },
    Info,
    Doctor,
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommand,
    },
    Benchmark {
        #[arg(long)]
        output: PathBuf,
    },
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    Search {
        #[arg(long)]
        room: String,
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long)]
        thread: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    Room {
        #[command(subcommand)]
        command: RoomCommand,
    },
    Scan {
        #[arg(long)]
        room: Option<String>,
        #[arg(long)]
        stdin: bool,
        #[arg(long, default_value = "text")]
        input: InputFormat,
        #[arg(long)]
        offline: bool,
    },
    Prepare {
        #[arg(long)]
        room: String,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        redact: bool,
        #[arg(long, default_value = "text")]
        input: InputFormat,
    },
    Preview {
        #[arg(long)]
        prepared: String,
    },
    Post {
        #[arg(long)]
        room: String,
        #[arg(long)]
        stdin: bool,
        #[arg(long, default_value = "text")]
        input: InputFormat,
        #[arg(long)]
        prepared: Option<String>,
        #[arg(long)]
        request: Option<String>,
        #[arg(long, default_value = "delivered")]
        wait: Wait,
        #[arg(long, default_value_t = 5)]
        timeout_seconds: u64,
        #[arg(long)]
        public: bool,
        #[arg(long)]
        reply_to: Option<String>,
        #[arg(long)]
        resolution: Option<Resolution>,
    },
    Status {
        #[arg(long = "message", alias = "request")]
        message: String,
    },
    Inbox {
        #[arg(long)]
        room: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}
#[derive(Subcommand)]
enum KnowledgeCommand {
    Publish {
        #[arg(long)]
        room: String,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        public: bool,
        /// JSON automation challenge answers; contains no daemon credentials.
        #[arg(long)]
        proof: Option<PathBuf>,
    },
    Search {
        #[arg(long)]
        room: String,
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long)]
        explore: bool,
    },
    Get {
        #[arg(long)]
        room: String,
        #[arg(long)]
        id: String,
    },
    Evaluate {
        #[arg(long)]
        room: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        proof: Option<PathBuf>,
    },
    Peers {
        #[arg(long)]
        room: String,
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long)]
        explore: bool,
    },
    Status {
        #[arg(long)]
        room: Option<String>,
    },
}
fn stdin_json<T: serde::de::DeserializeOwned>(explicit: bool) -> Result<T> {
    if !explicit || std::io::stdin().is_terminal() {
        return Err(Error::new(30, "stdin_required"));
    }
    read_json(std::io::stdin())
}
fn read_json<T: serde::de::DeserializeOwned>(reader: impl Read) -> Result<T> {
    let mut bytes = vec![];
    reader
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new(22, "input_unreadable"))?;
    if bytes.len() > 65536 {
        return Err(Error::new(22, "input_limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| INVALID)
}

fn read_proof(path: Option<&Path>) -> Result<Option<idobata::automation::AutomationAnswer>> {
    path.map(|path| {
        let bytes = util::read_bounded(path, 65_536)?;
        serde_json::from_slice(&bytes).map_err(|_| INVALID)
    })
    .transpose()
}

fn resolve_endpoint(
    socket: Option<&str>,
    home: &Path,
    home_explicit: bool,
    shared: impl FnOnce() -> Result<String>,
) -> Result<String> {
    if let Some(socket) = socket {
        return Ok(socket.into());
    }
    let local_config = if home_explicit {
        true
    } else {
        match std::fs::symlink_metadata(home.join("config.json")) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(idobata::error::STORAGE),
        }
    };
    if local_config {
        // Config contains the endpoint. Client selection never opens identity.key
        // or storage.key and never probes a dedicated daemon's private home.
        return Ok(config::load(home)?.endpoint);
    }
    shared()
}

fn shared_endpoint() -> Result<String> {
    #[cfg(windows)]
    {
        read_public_endpoint(Path::new(r"C:\Program Files\idobata\agent.socket"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok("/Library/Caches/idobata-runtime/ipc.sock".into())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok("/run/idobata/ipc.sock".into())
    }
}

#[cfg(any(windows, test))]
fn read_public_endpoint(path: &Path) -> Result<String> {
    let bytes = util::read_bounded(path, 512)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| INVALID)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(INVALID);
    }
    Ok(text.into())
}
#[derive(Subcommand)]
enum RoomCommand {
    Leave {
        #[arg(long)]
        room: String,
    },
    #[command(alias = "invite")]
    Create {
        #[arg(long)]
        room: String,
        #[arg(long)]
        members_file: PathBuf,
        #[arg(long, default_value_t = 24)]
        expires_hours: u64,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        public: bool,
        #[arg(long)]
        require_automation: bool,
        #[arg(long)]
        operators_file: Option<PathBuf>,
    },
    Join {
        #[arg(long)]
        room: String,
        #[arg(long)]
        invite_file: PathBuf,
        #[arg(long)]
        trust_authority: String,
    },
    Export {
        #[arg(long)]
        room: String,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum PublicCommand {
    Publish {
        #[arg(long)]
        feed: PathBuf,
        #[arg(long)]
        stdin: bool,
        #[arg(long, default_value = "json")]
        input: InputFormat,
        #[arg(long)]
        confirm_public: bool,
    },
    Verify {
        #[arg(long)]
        feed: PathBuf,
        /// 信頼済みの経路で確認した公開鍵(JSON文字列)のファイル。
        #[arg(long)]
        trust_publisher: PathBuf,
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        #[arg(long)]
        trust_bundle: Option<PathBuf>,
    },
    Trust {
        #[arg(long)]
        grants: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        revoke: Vec<String>,
    },
    Refresh {
        #[arg(long)]
        feed: PathBuf,
        #[arg(long)]
        room: Option<String>,
        #[arg(long)]
        withdraw: Option<String>,
        #[arg(long, default_value_t = 86400)]
        ttl_seconds: u64,
    },
}
#[derive(Subcommand)]
enum ReleaseCommand {
    Create {
        #[arg(long)]
        keys_home: PathBuf,
        #[arg(long)]
        targets_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        revision: u64,
    },
    Download {
        #[arg(long)]
        root_file: PathBuf,
        #[arg(long, default_value = "https://idobata.s21g.com/updates/")]
        metadata_url: String,
        #[arg(long, default_value = "https://idobata.s21g.com/releases/")]
        targets_url: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum BootstrapCommand {
    Create {
        #[arg(long)]
        node_home: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        revision: u64,
    },
    Fetch {
        #[arg(long)]
        trust_publisher: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum InputFormat {
    Text,
    Json,
}
#[derive(Clone, Copy, ValueEnum)]
enum Wait {
    Delivered,
    Accepted,
}
fn stdin_draft(explicit: bool, format: InputFormat) -> Result<Draft> {
    if !explicit || std::io::stdin().is_terminal() {
        return Err(Error::new(30, "stdin_required"));
    }
    let mut bytes = vec![];
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new(22, "input_unreadable"))?;
    if bytes.len() > 65536 {
        return Err(Error::new(22, "input_limit"));
    }
    match format {
        InputFormat::Text => Ok(Draft::plain(
            String::from_utf8(bytes).map_err(|_| Error::new(22, "invalid_utf8"))?,
        )),
        InputFormat::Json => serde_json::from_slice(&bytes).map_err(|_| INVALID),
    }
}
fn export(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if path.exists() {
        return Err(Error::new(30, "output_already_exists"));
    }
    util::atomic_write(path, &util::canonical(value)?)
}
fn print(value: &impl serde::Serialize) {
    println!("{}", serde_json::to_string(value).expect("JSON output"));
}
type PublicationState = (publication::Feed, Vec<String>, u64, Vec<String>);
fn publication_state(
    home: &Path,
    feed: &Path,
    key: &libp2p::identity::Keypair,
) -> Result<PublicationState> {
    let own = crypto::public(key);
    let root_path = home.join("trust-root.json");
    let bundle_path = home.join("trust.json");
    if root_path.exists() != bundle_path.exists() {
        return Err(INVALID);
    }
    let trust = if root_path.exists() {
        let root: String =
            serde_json::from_slice(&util::read_bounded(&root_path, 1024)?).map_err(|_| INVALID)?;
        let trust: Signed<idobata::trust::Trust> =
            serde_json::from_slice(&util::read_bounded(&bundle_path, 65536)?)
                .map_err(|_| INVALID)?;
        idobata::trust::verify(&trust, &root, util::now(), None)?;
        if !idobata::trust::allowed(&trust, &own, util::now()) {
            return Err(INVALID);
        }
        Some(trust)
    } else {
        None
    };
    let keys = trust
        .as_ref()
        .map(|t| {
            t.signed
                .keys
                .iter()
                .filter(|g| !t.signed.revoked.contains(&g.public_key))
                .map(|g| g.public_key.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![own.clone()]);
    let (f, w, r) = if !feed.exists() {
        (
            publication::Feed {
                version: 1,
                updated_at: util::now(),
                posts: vec![],
            },
            vec![],
            0,
        )
    } else if let Some(trust) = &trust {
        let bytes = util::read_bounded(feed, publication::MAX_FEED_BYTES)?;
        if let Ok(doc) = serde_json::from_slice::<Signed<publication::Manifest>>(&bytes) {
            if !idobata::trust::allowed(trust, &doc.public_key, doc.signed.issued_at) {
                return Err(INVALID);
            }
            publication::verify_manifest_with_keys(
                &doc,
                &doc.public_key,
                &keys,
                util::now().min(doc.signed.expires_at.saturating_sub(1)),
                None,
            )?;
            (doc.signed.feed, doc.signed.withdrawn, doc.signed.revision)
        } else {
            let f: publication::Feed = serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
            publication::verify_with_keys(&f, &keys, util::now())?;
            (f, vec![], 0)
        }
    } else {
        publication::decode(
            &util::read_bounded(feed, publication::MAX_FEED_BYTES)?,
            &own,
            util::now(),
            true,
        )?
    };
    if let Some(t) = &trust {
        for post in &f.posts {
            if !idobata::trust::allowed(t, &post.public_key, post.signed.published_at) {
                return Err(INVALID);
            }
        }
    }
    Ok((f, w, r, keys))
}
async fn execute(cli: Cli) -> Result<i32> {
    let home_explicit = cli.home.is_some();
    let home = cli.home.unwrap_or_else(|| PathBuf::from(".idobata"));
    let endpoint =
        || resolve_endpoint(cli.socket.as_deref(), &home, home_explicit, shared_endpoint);
    let request = match cli.command {
        Command::Bootstrap { command } => {
            match command {
                BootstrapCommand::Create {
                    node_home,
                    output,
                    revision,
                } => {
                    let node = crypto::load_key(&node_home)?;
                    let key = crypto::load_key(&home)?;
                    let doc = idobata::bootstrap::create(&node, &key, revision, util::now())?;
                    idobata::bootstrap::verify(&doc, &crypto::public(&key), util::now(), None)?;
                    util::atomic_write(&output, &util::canonical(&doc)?)?;
                    print(
                        &json!({"status":"signed","revision":revision,"expires_at":doc.signed.expires_at}),
                    );
                }
                BootstrapCommand::Fetch {
                    trust_publisher,
                    checkpoint,
                    output,
                } => {
                    let key: String =
                        serde_json::from_slice(&util::read_bounded(&trust_publisher, 1024)?)
                            .map_err(|_| INVALID)?;
                    let client = reqwest::Client::builder()
                        .timeout(Duration::from_secs(15))
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .map_err(|_| INVALID)?;
                    let response = client
                        .get("https://idobata.s21g.com/.well-known/idobata/bootstrap.json")
                        .send()
                        .await
                        .map_err(|_| NETWORK)?;
                    if !response.status().is_success() {
                        return Err(NETWORK);
                    }
                    let mut bytes = vec![];
                    let mut response = response;
                    while let Some(chunk) = response.chunk().await.map_err(|_| NETWORK)? {
                        if bytes.len() + chunk.len() > 65536 {
                            return Err(INVALID);
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    let doc: idobata::bootstrap::Document =
                        serde_json::from_slice(&bytes).map_err(|_| INVALID)?;
                    let old = if checkpoint.exists() {
                        Some(
                            serde_json::from_slice::<publication::Checkpoint>(&util::read_bounded(
                                &checkpoint,
                                1024,
                            )?)
                            .map_err(|_| INVALID)?,
                        )
                    } else {
                        None
                    };
                    let next = idobata::bootstrap::verify(&doc, &key, util::now(), old.as_ref())?;
                    util::atomic_write(&output, &util::canonical(&doc)?)?;
                    util::atomic_write(&checkpoint, &util::canonical(&next)?)?;
                    print(
                        &json!({"status":"verified","revision":next.revision,"peers":doc.signed.peers.len(),"room_authorization_required":true}),
                    );
                }
            }
            return Ok(0);
        }
        Command::Benchmark { output } => {
            print(&idobata::benchmark::run(&output)?);
            return Ok(0);
        }
        Command::Release { command } => {
            let value = match command {
                ReleaseCommand::Create {
                    keys_home,
                    targets_dir,
                    output,
                    revision,
                } => idobata::releases::create(&keys_home, &targets_dir, &output, revision)?,
                ReleaseCommand::Download {
                    root_file,
                    metadata_url,
                    targets_url,
                    target,
                    state,
                    output,
                } => {
                    idobata::releases::download(
                        &root_file,
                        &metadata_url,
                        &targets_url,
                        &target,
                        &state,
                        &output,
                    )
                    .await?
                }
            };
            print(&value);
            return Ok(0);
        }
        Command::Init { listen } => {
            let member = config::init(&home, listen)?;
            print(
                &json!({"status":"initialized","identity":member,"endpoint":config::load(&home)?.endpoint}),
            );
            return Ok(0);
        }
        Command::Identity { address } => {
            print(&config::identity(&home, address)?);
            return Ok(0);
        }
        Command::Daemon => {
            daemon::run(&home).await?;
            return Ok(0);
        }
        Command::Profile => {
            print(&json!({"policy_id":Scanner::policy_id(),"profile":Scanner::profile()}));
            return Ok(0);
        }
        Command::Public { command } => {
            match command {
                PublicCommand::Publish {
                    feed,
                    stdin,
                    input,
                    confirm_public,
                } => {
                    if !confirm_public {
                        return Err(Error::new(30, "confirm_public_required"));
                    }
                    let draft = stdin_draft(stdin, input)?;
                    util::protected(&home)?;
                    // 同じ公開ファイルの更新を直列化する。daemonの状態は開かない。
                    let lock = std::fs::OpenOptions::new()
                        .read(true)
                        .open(home.join("identity.key"))
                        .map_err(|_| INVALID)?;
                    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| INVALID)?;
                    let key = crypto::load_key(&home)?;
                    let (existing, withdrawn, revision, keys) =
                        publication_state(&home, &feed, &key)?;
                    let public = publication::append_with_keys(
                        Some(existing),
                        &key,
                        draft,
                        true,
                        util::now(),
                        &keys,
                    )?;
                    let sealed = publication::seal_with_keys(
                        public.clone(),
                        withdrawn,
                        revision.checked_add(1).ok_or(INVALID)?,
                        &key,
                        util::now(),
                        86400,
                        &keys,
                    )?;
                    util::atomic_write(&feed, &util::canonical(&sealed)?)?;
                    print(&json!({"status":"published","count":public.posts.len(),
                        "id":public.posts[0].signed.id,"public_key":crypto::public(&key)}));
                }
                PublicCommand::Verify {
                    feed,
                    trust_publisher,
                    checkpoint,
                    trust_bundle,
                } => {
                    let key = serde_json::from_slice::<String>(&util::read_bounded(
                        &trust_publisher,
                        1024,
                    )?)
                    .map_err(|_| INVALID)?;
                    let public = serde_json::from_slice::<Signed<publication::Manifest>>(
                        &util::read_bounded(&feed, publication::MAX_FEED_BYTES)?,
                    )
                    .map_err(|_| INVALID)?;
                    let old = if let Some(path) = &checkpoint {
                        if path.exists() {
                            Some(
                                serde_json::from_slice::<publication::Checkpoint>(
                                    &util::read_bounded(path, 1024)?,
                                )
                                .map_err(|_| INVALID)?,
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let next = if let Some(path) = trust_bundle {
                        let trust: Signed<idobata::trust::Trust> =
                            serde_json::from_slice(&util::read_bounded(&path, 65536)?)
                                .map_err(|_| INVALID)?;
                        idobata::trust::verify_feed(
                            &public,
                            &trust,
                            &key,
                            util::now(),
                            old.as_ref(),
                        )?
                    } else {
                        publication::verify_manifest(&public, &key, util::now(), old.as_ref())?
                    };
                    if let Some(path) = checkpoint {
                        util::atomic_write(&path, &util::canonical(&next)?)?;
                    }
                    print(&json!({"status":"verified","count":public.signed.count,
                        "revision":public.signed.revision,"expires_at":public.signed.expires_at,
                        "generated_at":public.signed.issued_at,"updated_at":public.signed.feed.updated_at}));
                }
                PublicCommand::Trust {
                    grants,
                    output,
                    revision,
                    revoke,
                } => {
                    let keys: Vec<idobata::trust::Grant> =
                        serde_json::from_slice(&util::read_bounded(&grants, 65536)?)
                            .map_err(|_| INVALID)?;
                    let root = crypto::load_key(&home)?;
                    let trust = idobata::trust::create(&root, keys, revoke, revision, util::now())?;
                    util::atomic_write(&output, &util::canonical(&trust)?)?;
                    print(
                        &json!({"status":"authorized","revision":revision,"keys":trust.signed.keys.len()}),
                    );
                }
                PublicCommand::Refresh {
                    feed,
                    room,
                    withdraw,
                    ttl_seconds,
                } => {
                    util::protected(&home)?;
                    let lock = std::fs::OpenOptions::new()
                        .read(true)
                        .open(home.join("identity.key"))
                        .map_err(|_| INVALID)?;
                    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| INVALID)?;
                    let key = crypto::load_key(&home)?;
                    let (mut f, mut w, r, keys) = publication_state(&home, &feed, &key)?;
                    if let Some(room) = room {
                        let mut before = None;
                        let mut all = Vec::new();
                        let mut cursors = std::collections::BTreeSet::new();
                        // ID cursorなので、途中に新着があっても既読の境界は変わらない。
                        loop {
                            let result = ipc::call(
                                &endpoint()?,
                                &Request::PublicSnapshot {
                                    room: room.clone(),
                                    before,
                                },
                            )
                            .await?;
                            if result.code != 0 {
                                print(&result.result);
                                return Ok(result.code);
                            }
                            let entries: Vec<publication::PublicEntry> =
                                serde_json::from_value(result.result["entries"].clone())
                                    .map_err(|_| INVALID)?;
                            all.extend(entries);
                            all.truncate(50);
                            before = result.result["next_before"].as_str().map(str::to_owned);
                            if all.len() >= 50 || before.is_none() {
                                break;
                            }
                            if !cursors.insert(before.clone()) {
                                return Err(INVALID);
                            }
                        }
                        all.retain(|e| !w.contains(&e.origin.message_id));
                        publication::import_with_keys(&mut f, &key, all, util::now(), &keys)?;
                    }
                    if let Some(id) = withdraw {
                        if !util::valid_id(&id) {
                            return Err(INVALID);
                        }
                        if !f.posts.iter().any(|p| p.signed.id == id) && !w.contains(&id) {
                            return Err(INVALID);
                        }
                        f.posts.retain(|p| p.signed.id != id);
                        if !w.contains(&id) {
                            w.push(id);
                        }
                    }
                    let sealed = publication::seal_with_keys(
                        f,
                        w,
                        r.checked_add(1).ok_or(INVALID)?,
                        &key,
                        util::now(),
                        ttl_seconds,
                        &keys,
                    )?;
                    util::atomic_write(&feed, &util::canonical(&sealed)?)?;
                    print(
                        &json!({"status":"refreshed","count":sealed.signed.count,"revision":sealed.signed.revision}),
                    );
                }
            }
            return Ok(0);
        }
        Command::Room { command } => {
            match command {
                RoomCommand::Leave { room } => {
                    config::leave_room(&home, &room)?;
                    print(&json!({"status":"room_left"}));
                }
                RoomCommand::Create {
                    room,
                    members_file,
                    expires_hours,
                    output,
                    public,
                    require_automation,
                    operators_file,
                } => {
                    let members = serde_json::from_slice::<Vec<Member>>(&util::read_bounded(
                        &members_file,
                        65536,
                    )?)
                    .map_err(|_| INVALID)?;
                    if output.exists() {
                        return Err(INVALID);
                    }
                    let operators = operators_file
                        .map(|path| {
                            serde_json::from_slice::<idobata::knowledge_abuse::OperatorClaims>(
                                &util::read_bounded(&path, 65536)?,
                            )
                            .map_err(|_| INVALID)
                        })
                        .transpose()?;
                    let cert = config::create_room_with_operators(
                        &home,
                        &room,
                        members,
                        expires_hours,
                        public,
                        require_automation,
                        operators,
                    )?;
                    export(&output, &cert)?;
                    print(
                        &json!({"status":"room_created","authority_peer_id":crypto::public_key(&cert.public_key)?.to_peer_id().to_string(),"epoch":cert.signed.epoch}),
                    );
                }
                RoomCommand::Join {
                    room,
                    invite_file,
                    trust_authority,
                } => {
                    util::protected(&invite_file)?;
                    let cert = serde_json::from_slice::<Signed<Room>>(&util::read_bounded(
                        &invite_file,
                        65536,
                    )?)
                    .map_err(|_| INVALID)?;
                    config::join_room(&home, &room, cert, &trust_authority)?;
                    print(&json!({"status":"room_joined"}));
                }
                RoomCommand::Export { room, output } => {
                    let c = config::load(&home)?;
                    let cert = &c.rooms.get(&room).ok_or(INVALID)?.certificate;
                    export(&output, cert)?;
                    print(&json!({"status":"room_exported"}));
                }
            }
            return Ok(0);
        }
        Command::Knowledge { command } => match command {
            KnowledgeCommand::Publish {
                room,
                stdin,
                public,
                proof,
            } => Request::KnowledgePublish {
                room,
                input: stdin_json(stdin)?,
                public,
                proof: read_proof(proof.as_deref())?,
            },
            KnowledgeCommand::Search {
                room,
                query,
                limit,
                explore,
            } => Request::KnowledgeSearch {
                room,
                query,
                limit,
                explore,
            },
            KnowledgeCommand::Get { room, id } => Request::KnowledgeGet { room, id },
            KnowledgeCommand::Evaluate {
                room,
                id,
                stdin,
                proof,
            } => Request::KnowledgeEvaluate {
                room,
                id,
                input: stdin_json(stdin)?,
                proof: read_proof(proof.as_deref())?,
            },
            KnowledgeCommand::Peers {
                room,
                query,
                limit,
                explore,
            } => Request::KnowledgePeers {
                room,
                query,
                limit,
                explore,
            },
            KnowledgeCommand::Status { room } => Request::KnowledgeStatus { room },
        },
        Command::Info => Request::Info,
        Command::Doctor => {
            let reply = ipc::call(&endpoint()?, &Request::Info).await?;
            let rooms = reply.result["rooms"].as_array().ok_or(INVALID)?;
            let ok = rooms.iter().all(|r| r["authorized"] == true);
            print(
                &json!({"status":if ok {"healthy"} else {"degraded"},"daemon":reply.result,
                "checked_at":util::now(),"scope":"local-authorized-configuration","untrusted":false}),
            );
            return Ok(if ok { 0 } else { 30 });
        }
        Command::Search {
            room,
            query,
            thread,
            limit,
        } => Request::Search {
            room,
            query,
            thread,
            limit,
        },
        Command::Scan {
            room,
            stdin,
            input,
            offline,
        } => {
            let draft = stdin_draft(stdin, input)?;
            if offline {
                crypto::validate_draft(&draft)?;
                let report = Scanner::new()?.scan(&draft, false)?;
                let mut value = serde_json::to_value(&report).map_err(|_| INVALID)?;
                value["enqueued"] = false.into();
                value["policy_id"] = Scanner::policy_id().into();
                print(&value);
                return Ok(report.code);
            }
            Request::Scan {
                room: room.ok_or(INVALID)?,
                draft,
            }
        }
        Command::Prepare {
            room,
            stdin,
            redact,
            input,
        } => {
            if !redact {
                return Err(INVALID);
            }
            Request::Prepare {
                room,
                draft: stdin_draft(stdin, input)?,
            }
        }
        Command::Preview { prepared } => Request::Preview { prepared },
        Command::Status { message } => Request::Status {
            request_id: message,
        },
        Command::Inbox { room, limit } => Request::Inbox { room, limit },
        Command::Post {
            room,
            stdin,
            input,
            prepared,
            request,
            wait,
            timeout_seconds,
            public,
            reply_to,
            resolution,
        } => {
            if timeout_seconds > 60 || stdin == prepared.is_some() {
                return Err(INVALID);
            }
            let draft = if prepared.is_none() {
                Some(stdin_draft(stdin, input)?)
            } else {
                None
            };
            let ep = endpoint()?;
            let id = if let Some(id) = request {
                if !util::valid_id(&id) {
                    return Err(INVALID);
                }
                id
            } else {
                let begin = ipc::call(&ep, &Request::Begin).await?;
                if begin.code != 0 {
                    print(&begin.result);
                    return Ok(begin.code);
                }
                begin
                    .result
                    .get("request_id")
                    .and_then(|x| x.as_str())
                    .ok_or(INVALID)?
                    .to_string()
            };
            let mut reply = match ipc::call(
                &ep,
                &Request::Post {
                    room,
                    draft,
                    prepared,
                    request_id: id.clone(),
                    options: PostOptions {
                        public,
                        reply_to,
                        resolution,
                    },
                },
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    print(
                        &json!({"status":"unknown","error":e.error,"request_id":id,"enqueued":"unknown"}),
                    );
                    return Ok(e.code);
                }
            };
            if reply.code == 10 && matches!(wait, Wait::Accepted) {
                reply.code = 0
            } else if reply.code == 10 {
                let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
                while Instant::now() < deadline && reply.code == 10 {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    reply = match ipc::call(
                        &ep,
                        &Request::Status {
                            request_id: id.clone(),
                        },
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => {
                            print(
                                &json!({"status":"unknown","enqueued":true,"request_id":id,"error":"status_unavailable"}),
                            );
                            return Ok(NETWORK.code);
                        }
                    };
                }
            }
            print(&reply.result);
            return Ok(reply.code);
        }
    };
    let reply = ipc::call(&endpoint()?, &request).await?;
    print(&reply.result);
    Ok(reply.code)
}
#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    util::disable_core_dumps();
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => match e.kind() {
            clap::error::ErrorKind::DisplayHelp => {
                let _ = e.print();
                std::process::exit(0)
            }
            clap::error::ErrorKind::DisplayVersion => {
                println!("idobata {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0)
            }
            _ => {
                print(&json!({"status":"invalid","error":"invalid_cli_arguments"}));
                std::process::exit(30)
            }
        },
    };
    let code = match execute(cli).await {
        Ok(code) => code,
        Err(e) => {
            print(&json!({"status":"failed","error":e.error,"enqueued":false}));
            e.code
        }
    };
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use idobata::knowledge::{KnowledgeInput, ReviewInput};

    #[test]
    fn knowledge_cli_accepts_all_agent_operations_and_global_endpoint_flags() {
        for operation in ["publish", "search", "get", "evaluate", "peers", "status"] {
            let mut args = vec!["idobata", "knowledge", operation, "--room", "engineering"];
            if ["get", "evaluate"].contains(&operation) {
                args.extend(["--id", "record-id"]);
            }
            if ["publish", "evaluate"].contains(&operation) {
                args.push("--stdin");
            }
            args.extend(["--socket", "/run/idobata/ipc.sock", "--json"]);
            let cli = Cli::try_parse_from(args).unwrap();
            assert_eq!(cli.socket.as_deref(), Some("/run/idobata/ipc.sock"));
            assert!(cli.json);
            assert!(matches!(cli.command, Command::Knowledge { .. }));
        }
        let cli = Cli::try_parse_from(["idobata", "knowledge", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Knowledge {
                command: KnowledgeCommand::Status { room: None }
            }
        ));
    }

    #[test]
    fn knowledge_search_defaults_allow_browsing_without_implicit_room_selection() {
        let cli = Cli::try_parse_from(["idobata", "knowledge", "search", "--room", "engineering"])
            .unwrap();
        let Command::Knowledge {
            command:
                KnowledgeCommand::Search {
                    room,
                    query,
                    limit,
                    explore: false,
                },
        } = cli.command
        else {
            panic!("wrong command");
        };
        assert_eq!(room, "engineering");
        assert!(query.is_empty());
        assert_eq!(limit, 10);
        assert!(
            Cli::try_parse_from(["idobata", "knowledge", "search", "--query", "retry"]).is_err()
        );
    }

    #[test]
    fn knowledge_json_rejects_unknown_duplicate_and_trailing_input() {
        let input: KnowledgeInput =
            read_json(br#"{"problem":"retry","solution":"bounded backoff"}"#.as_slice()).unwrap();
        assert_eq!(input.kind, "answer");
        assert!(
            read_json::<KnowledgeInput>(
                br#"{"problem":"retry","solution":"backoff","environment":"collect"}"#.as_slice()
            )
            .is_err()
        );
        assert!(
            read_json::<KnowledgeInput>(
                br#"{"problem":"one","problem":"two","solution":"backoff"}"#.as_slice()
            )
            .is_err()
        );
        assert!(
            read_json::<KnowledgeInput>(
                br#"{"problem":"retry","solution":"backoff"} {}"#.as_slice()
            )
            .is_err()
        );
        assert!(
            read_json::<ReviewInput>(
                br#"{"verdict":"useful","evidence":"retried successfully","extra":"field"}"#
                    .as_slice()
            )
            .is_err()
        );
    }

    #[test]
    fn knowledge_json_is_bounded_before_parsing() {
        let bytes = vec![b' '; 65_537];
        let error = match read_json::<KnowledgeInput>(bytes.as_slice()) {
            Ok(_) => panic!("oversized input accepted"),
            Err(error) => error,
        };
        assert_eq!(error.error, "input_limit");
    }

    #[test]
    fn explicit_home_provenance_and_automation_flags_survive_cli_parsing() {
        for args in [
            vec!["idobata", "--home", ".idobata", "info"],
            vec!["idobata", "--home=.idobata", "info"],
        ] {
            assert_eq!(
                Cli::try_parse_from(args).unwrap().home,
                Some(PathBuf::from(".idobata"))
            );
        }
        assert!(
            Cli::try_parse_from(["idobata", "info"])
                .unwrap()
                .home
                .is_none()
        );
        let cli = Cli::try_parse_from([
            "idobata",
            "knowledge",
            "publish",
            "--room",
            "engineering",
            "--stdin",
            "--proof",
            "answer.json",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Command::Knowledge { command: KnowledgeCommand::Publish { proof: Some(path), public: false, .. } } if path == Path::new("answer.json"))
        );
        let cli = Cli::try_parse_from([
            "idobata",
            "room",
            "create",
            "--room",
            "engineering",
            "--members-file",
            "members.json",
            "--output",
            "invite.json",
            "--require-automation",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Room {
                command: RoomCommand::Create {
                    require_automation: true,
                    ..
                }
            }
        ));
    }

    #[test]
    fn operator_policy_and_explicit_exploration_survive_cli_parsing() {
        for action in ["search", "peers"] {
            let ordinary =
                Cli::try_parse_from(["idobata", "knowledge", action, "--room", "engineering"])
                    .unwrap();
            assert!(matches!(
                ordinary.command,
                Command::Knowledge {
                    command: KnowledgeCommand::Search { explore: false, .. }
                        | KnowledgeCommand::Peers { explore: false, .. }
                }
            ));
            let explicit = Cli::try_parse_from([
                "idobata",
                "knowledge",
                action,
                "--room",
                "engineering",
                "--explore",
            ])
            .unwrap();
            assert!(matches!(
                explicit.command,
                Command::Knowledge {
                    command: KnowledgeCommand::Search { explore: true, .. }
                        | KnowledgeCommand::Peers { explore: true, .. }
                }
            ));
        }
        for action in ["create", "invite"] {
            let parsed = Cli::try_parse_from([
                "idobata",
                "room",
                action,
                "--room",
                "engineering",
                "--members-file",
                "members.json",
                "--output",
                "invite.json",
                "--operators-file",
                "operators.json",
                "--require-automation",
            ])
            .unwrap();
            assert!(matches!(parsed.command, Command::Room { command:
                RoomCommand::Create { operators_file: Some(path), require_automation: true, .. }
            } if path == Path::new("operators.json")));
        }
    }

    #[test]
    fn endpoint_overrides_never_fall_through_to_another_node() {
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("missing");
        assert_eq!(
            resolve_endpoint(Some("explicit.sock"), &home, true, || panic!(
                "unexpected shared endpoint read"
            ))
            .unwrap(),
            "explicit.sock"
        );
        assert!(resolve_endpoint(None, &home, true, || Ok("shared.sock".into())).is_err());
        assert_eq!(
            resolve_endpoint(None, &home, false, || Ok("shared.sock".into())).unwrap(),
            "shared.sock"
        );
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("config.json"), "invalid configuration").unwrap();
        assert!(
            resolve_endpoint(None, &home, false, || panic!(
                "invalid local configuration must fail closed"
            ))
            .is_err()
        );
        assert_eq!(
            resolve_endpoint(Some("explicit.sock"), &home, false, || panic!(
                "unexpected fallback"
            ))
            .unwrap(),
            "explicit.sock"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_endpoint_selection_does_not_read_node_keys() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let home = temporary.path().join("node");
        config::init(&home, vec!["/ip4/127.0.0.1/tcp/0".into()]).unwrap();
        let expected = config::load(&home).unwrap().endpoint;
        for key in ["identity.key", "storage.key"] {
            std::fs::write(home.join(key), "invalid key that must never be decoded").unwrap();
            std::fs::set_permissions(home.join(key), std::fs::Permissions::from_mode(0o0)).unwrap();
        }
        assert_eq!(
            resolve_endpoint(None, &home, false, || panic!("local endpoint ignored")).unwrap(),
            expected
        );
        assert_eq!(
            resolve_endpoint(None, &home, true, || panic!("explicit home ignored")).unwrap(),
            expected
        );
        std::fs::remove_file(home.join("config.json")).unwrap();
        assert_eq!(
            resolve_endpoint(None, &home, false, || Ok("shared.sock".into())).unwrap(),
            "shared.sock"
        );
    }

    #[test]
    fn public_locator_and_automation_answers_are_bounded_data_files() {
        let temporary = tempfile::tempdir().unwrap();
        let locator = temporary.path().join("agent.socket");
        std::fs::write(&locator, "shared.sock\r\n").unwrap();
        assert_eq!(read_public_endpoint(&locator).unwrap(), "shared.sock");
        for invalid in [vec![b'x'; 513], b"one\ntwo".to_vec(), vec![0xff], vec![]] {
            std::fs::write(&locator, invalid).unwrap();
            assert!(read_public_endpoint(&locator).is_err());
        }
        assert!(read_proof(None).unwrap().is_none());
        let proof = temporary.path().join("answer.json");
        std::fs::write(&proof, vec![b' '; 65_537]).unwrap();
        assert!(read_proof(Some(&proof)).is_err());
        std::fs::write(&proof, b"{}").unwrap();
        assert!(read_proof(Some(&proof)).is_err());
    }
}
