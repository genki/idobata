use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
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
    about = "Inspected, authenticated P2P messages for AI agents"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".idobata")]
    home: PathBuf,
    #[arg(long, global = true)]
    socket: Option<String>,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
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
enum RoomCommand {
    Create {
        #[arg(long)]
        room: String,
        #[arg(long)]
        members_file: PathBuf,
        #[arg(long, default_value_t = 24)]
        expires_hours: u64,
        #[arg(long)]
        output: PathBuf,
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
async fn execute(cli: Cli) -> Result<i32> {
    let endpoint = || -> Result<String> {
        if let Some(s) = &cli.socket {
            Ok(s.clone())
        } else {
            Ok(config::load(&cli.home)?.endpoint)
        }
    };
    let request = match cli.command {
        Command::Init { listen } => {
            let member = config::init(&cli.home, listen)?;
            print(
                &json!({"status":"initialized","identity":member,"endpoint":config::load(&cli.home)?.endpoint}),
            );
            return Ok(0);
        }
        Command::Identity { address } => {
            print(&config::identity(&cli.home, address)?);
            return Ok(0);
        }
        Command::Daemon => {
            daemon::run(&cli.home).await?;
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
                    util::protected(&cli.home)?;
                    // 同じ公開ファイルの更新を直列化する。daemonの状態は開かない。
                    let lock = std::fs::OpenOptions::new()
                        .read(true)
                        .open(cli.home.join("identity.key"))
                        .map_err(|_| INVALID)?;
                    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| INVALID)?;
                    let existing = if feed.exists() {
                        Some(
                            serde_json::from_slice::<publication::Feed>(&util::read_bounded(
                                &feed,
                                publication::MAX_FEED_BYTES,
                            )?)
                            .map_err(|_| INVALID)?,
                        )
                    } else {
                        None
                    };
                    let key = crypto::load_key(&cli.home)?;
                    let public = publication::append(existing, &key, draft, true, util::now())?;
                    util::atomic_write(&feed, &util::canonical(&public)?)?;
                    print(&json!({"status":"published","count":public.posts.len(),
                        "id":public.posts[0].signed.id,"public_key":crypto::public(&key)}));
                }
                PublicCommand::Verify {
                    feed,
                    trust_publisher,
                } => {
                    let key = serde_json::from_slice::<String>(&util::read_bounded(
                        &trust_publisher,
                        1024,
                    )?)
                    .map_err(|_| INVALID)?;
                    let public = serde_json::from_slice::<publication::Feed>(&util::read_bounded(
                        &feed,
                        publication::MAX_FEED_BYTES,
                    )?)
                    .map_err(|_| INVALID)?;
                    publication::verify(&public, &key, util::now())?;
                    print(&json!({"status":"verified","count":public.posts.len(),
                        "updated_at":public.updated_at}));
                }
            }
            return Ok(0);
        }
        Command::Room { command } => {
            match command {
                RoomCommand::Create {
                    room,
                    members_file,
                    expires_hours,
                    output,
                } => {
                    let members = serde_json::from_slice::<Vec<Member>>(&util::read_bounded(
                        &members_file,
                        65536,
                    )?)
                    .map_err(|_| INVALID)?;
                    if output.exists() {
                        return Err(INVALID);
                    }
                    let cert = config::create_room(&cli.home, &room, members, expires_hours)?;
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
                    config::join_room(&cli.home, &room, cert, &trust_authority)?;
                    print(&json!({"status":"room_joined"}));
                }
                RoomCommand::Export { room, output } => {
                    let c = config::load(&cli.home)?;
                    let cert = &c.rooms.get(&room).ok_or(INVALID)?.certificate;
                    export(&output, cert)?;
                    print(&json!({"status":"room_exported"}));
                }
            }
            return Ok(0);
        }
        Command::Info => Request::Info,
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
    util::disable_core_dumps();
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => match e.kind() {
            clap::error::ErrorKind::DisplayHelp => {
                let _ = Cli::command().print_help();
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
