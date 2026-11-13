use std::{
    io::stdout,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use askar_explorer::{
    commands::{self, Format, ListOptions},
    describe::DescribeOptions,
    redact::{Policy, Redactor, View},
    source::{Query, Source, TagCondition},
};
use askar_storage::inspect::ExpiryFilter;
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "Inspect Askar storage without modifying the source database")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

/// Connection and output options shared by the read commands.
#[derive(ClapArgs)]
struct Connection {
    /// Askar SQLite or PostgreSQL URI.
    #[arg(long, env = "ASKAR_EXPLORER_URI")]
    uri: String,
    /// Read the store pass key from this environment variable instead of prompting.
    #[arg(long)]
    pass_key_env: Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t)]
    format: Format,
}

/// How much of the data a command may show.
#[derive(ClapArgs)]
struct Visibility {
    /// Show real values and tag values (key-manager values stay hidden).
    #[arg(long, conflicts_with = "redact")]
    reveal: bool,
    /// Show only shapes and pseudonyms allowed by the policy; this is the view for AI agents.
    #[arg(long)]
    redact: bool,
    /// Redaction policy file used with --redact.
    #[arg(long, env = "ASKAR_EXPLORER_POLICY")]
    policy: Option<PathBuf>,
}

impl Visibility {
    fn view(&self) -> Result<View> {
        Ok(if self.redact {
            View::Redacted(Arc::new(Redactor::open(self.policy.as_deref())?))
        } else if self.reveal {
            View::Reveal
        } else {
            View::Hidden
        })
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    Item,
    Kms,
    Any,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExpiryArg {
    Any,
    Live,
    Expired,
}

#[derive(Subcommand)]
enum ChangesAction {
    /// List proposals with their status.
    List,
    /// Show a proposal and the real before and after of each change.
    Show {
        /// Proposal id, such as p-3fa9c1d07b2e.
        id: String,
        #[command(flatten)]
        connection: ReadConnection,
    },
    /// Apply a proposal. Without --commit this only shows what would be written.
    Apply {
        /// Proposal id.
        id: String,
        #[command(flatten)]
        connection: ReadConnection,
        /// Connection allowed to write; applying is refused without one.
        #[arg(long, env = "ASKAR_EXPLORER_WRITE_URI")]
        write_uri: Option<String>,
        /// Write the changes after you confirm.
        #[arg(long)]
        commit: bool,
        /// Confirm that a recoverable backup of the store exists.
        #[arg(long)]
        confirm_backup: bool,
    },
    /// Turn a proposal down.
    Reject {
        /// Proposal id.
        id: String,
    },
}

#[derive(ClapArgs)]
struct ReadConnection {
    /// Askar SQLite or PostgreSQL URI used to read the store.
    #[arg(long, env = "ASKAR_EXPLORER_URI")]
    uri: String,
    /// Read the store pass key from this environment variable instead of prompting.
    #[arg(long)]
    pass_key_env: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// List profiles and whether their keys unlock.
    Profiles {
        #[command(flatten)]
        connection: Connection,
    },
    /// Count entries per category without showing any values.
    Stats {
        #[command(flatten)]
        connection: Connection,
        /// Only this profile.
        #[arg(long)]
        profile: Option<String>,
    },
    /// List entries; filters on category, name and tags run in the database.
    Ls {
        #[command(flatten)]
        connection: Connection,
        /// Only this profile.
        #[arg(long)]
        profile: Option<String>,
        /// Exact category.
        #[arg(long)]
        category: Option<String>,
        /// Exact entry name.
        #[arg(long)]
        name: Option<String>,
        /// Encrypted tag that must equal name=value (repeatable).
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Plaintext tag that must equal name=value (repeatable).
        #[arg(long = "ptag")]
        plaintext_tags: Vec<String>,
        /// Which kind of entries to list.
        #[arg(long, value_enum, default_value = "item")]
        kind: KindArg,
        /// Which entries to list by expiry.
        #[arg(long, value_enum, default_value = "any")]
        expiry: ExpiryArg,
        /// Maximum number of entries.
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// Continue after this entry id.
        #[arg(long, default_value_t = 0)]
        after_id: i64,
        #[command(flatten)]
        visibility: Visibility,
    },
    /// Show one entry by id.
    Get {
        #[command(flatten)]
        connection: Connection,
        /// Profile name; optional when the store has one profile.
        #[arg(long)]
        profile: Option<String>,
        /// Entry id, as shown by `ls`.
        #[arg(long)]
        id: i64,
        #[command(flatten)]
        visibility: Visibility,
    },
    /// Review and apply edits that an agent proposed; this is the only way they reach the store.
    Changes {
        /// Folder holding the proposals.
        #[arg(
            long,
            env = "ASKAR_EXPLORER_PROPOSALS",
            default_value = ".askar-explorer/proposals",
            global = true
        )]
        proposals: PathBuf,
        #[command(subcommand)]
        action: ChangesAction,
    },
    /// Run the read-only agent API, which always applies the redacted view.
    Serve {
        /// Askar SQLite or PostgreSQL URI.
        #[arg(long, env = "ASKAR_EXPLORER_URI")]
        uri: String,
        /// Read the store pass key from this environment variable instead of prompting.
        #[arg(long)]
        pass_key_env: Option<String>,
        /// Redaction policy; agents must not be able to write this file.
        #[arg(long, env = "ASKAR_EXPLORER_POLICY")]
        policy: Option<PathBuf>,
        /// Address for the agent API; expose it only to the agents' network.
        #[arg(
            long,
            env = "ASKAR_EXPLORER_AGENT_LISTEN",
            default_value = "127.0.0.1:7071"
        )]
        agent_listen: std::net::SocketAddr,
        /// Where to write the access token that agents present.
        #[arg(
            long,
            env = "ASKAR_EXPLORER_TOKEN_FILE",
            default_value = ".askar-explorer/agent.token"
        )]
        token_file: PathBuf,
        /// Where agents' proposals are kept for a person to review; agents cannot read it.
        #[arg(
            long,
            env = "ASKAR_EXPLORER_PROPOSALS",
            default_value = ".askar-explorer/proposals"
        )]
        proposals: PathBuf,
        /// How a person runs this tool, shown to agents so they can say what to review.
        #[arg(long, env = "ASKAR_EXPLORER_REVIEW_COMMAND")]
        review_command: Option<String>,
    },
    /// Run the web interface for people. It shows real, decrypted data, so it asks for the
    /// store pass key before showing anything.
    Ui {
        /// Askar SQLite or PostgreSQL URI (read-only access is enough to browse).
        #[arg(long, env = "ASKAR_EXPLORER_URI")]
        uri: String,
        /// Address to listen on; keep it on the loopback interface unless a container
        /// publishes it there.
        #[arg(
            long,
            env = "ASKAR_EXPLORER_UI_LISTEN",
            default_value = "127.0.0.1:7070"
        )]
        listen: std::net::SocketAddr,
        /// Host header values to accept (default: localhost and 127.0.0.1 on the port).
        #[arg(
            long = "allowed-host",
            env = "ASKAR_EXPLORER_UI_HOSTS",
            value_delimiter = ','
        )]
        allowed_hosts: Vec<String>,
        /// Seconds without use before the session locks and its keys are dropped.
        #[arg(long, env = "ASKAR_EXPLORER_UI_IDLE_SECONDS", default_value_t = 900)]
        idle_seconds: u64,
        /// Base seconds that logins are refused after five failures; doubles each time.
        #[arg(
            long,
            env = "ASKAR_EXPLORER_UI_LOCKOUT_SECONDS",
            default_value_t = 60,
            hide = true
        )]
        lockout_seconds: u64,
    },
    /// Serve MCP on stdio for an AI agent, forwarding to the agent API.
    Mcp {
        /// Base URL of the agent API.
        #[arg(
            long,
            env = "ASKAR_EXPLORER_AGENT_URL",
            default_value = "http://127.0.0.1:7071"
        )]
        agent_url: String,
        /// File holding the agent token, read on every request.
        #[arg(
            long,
            env = "ASKAR_EXPLORER_TOKEN_FILE",
            default_value = ".askar-explorer/agent.token"
        )]
        token_file: PathBuf,
    },
    /// Summarize the structure of one category: fields, types, counts and tags.
    Describe {
        #[command(flatten)]
        connection: Connection,
        /// Category to describe.
        category: String,
        /// Only this profile.
        #[arg(long)]
        profile: Option<String>,
        /// How many entries to inspect, in id order.
        #[arg(long, default_value_t = 500)]
        sample: usize,
        /// Policy file listing which values may be shown.
        #[arg(long, env = "ASKAR_EXPLORER_POLICY")]
        policy: Option<PathBuf>,
    },
    /// Run a read-only SQL query against the `items` table.
    Sql {
        #[command(flatten)]
        connection: Connection,
        /// A single SELECT statement, e.g. "SELECT category, count(*) FROM items GROUP BY 1".
        query: String,
        #[command(flatten)]
        visibility: Visibility,
        /// Maximum number of result rows.
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// Export decrypted items to a plaintext SQLite database.
    Export {
        /// Askar SQLite or PostgreSQL URI.
        #[arg(long, env = "ASKAR_EXPLORER_URI")]
        uri: String,
        /// New plaintext SQLite file to create.
        #[arg(long, env = "ASKAR_EXPLORER_OUT")]
        out: PathBuf,
        /// Include key-manager entries, which may contain private keys.
        #[arg(long)]
        include_kms: bool,
        /// Read the store pass key from this environment variable instead of prompting.
        #[arg(long)]
        pass_key_env: Option<String>,
    },
    /// Preview or apply edits made to a decrypted export.
    Apply {
        /// Source Askar store URI.
        #[arg(long, env = "ASKAR_EXPLORER_URI")]
        uri: String,
        /// Editable SQLite export file.
        #[arg(long, env = "ASKAR_EXPLORER_OUT")]
        edits: PathBuf,
        /// Write changes to Askar; without this flag only a plan is printed.
        #[arg(long, requires = "confirm_backup")]
        commit: bool,
        /// Confirm that a recoverable backup of the source store exists.
        #[arg(long)]
        confirm_backup: bool,
        /// Read the store pass key from this environment variable instead of prompting.
        #[arg(long)]
        pass_key_env: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    if Path::new(".env").exists() {
        dotenvy::from_path(".env").context("Cannot load .env")?;
    }
    let Args { command } = Args::parse();
    match command {
        Command::Profiles { connection } => {
            let source = Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            commands::profiles(&source, &mut stdout().lock(), connection.format)
        }
        Command::Stats {
            connection,
            profile,
        } => {
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            commands::stats(
                &mut source,
                profile.as_deref(),
                &mut stdout().lock(),
                connection.format,
            )
            .await
        }
        Command::Ls {
            connection,
            profile,
            category,
            name,
            tags,
            plaintext_tags,
            kind,
            expiry,
            limit,
            after_id,
            visibility,
        } => {
            let view = visibility.view()?;
            let mut conditions = Vec::new();
            for spec in &tags {
                conditions.push(TagCondition::parse(spec, false)?);
            }
            for spec in &plaintext_tags {
                conditions.push(TagCondition::parse(spec, true)?);
            }
            let query = Query {
                id: None,
                kind: match kind {
                    KindArg::Item => Some(2),
                    KindArg::Kms => Some(1),
                    KindArg::Any => None,
                },
                category,
                name,
                tags: conditions,
                expiry: match expiry {
                    ExpiryArg::Any => ExpiryFilter::Any,
                    ExpiryArg::Live => ExpiryFilter::LiveOnly,
                    ExpiryArg::Expired => ExpiryFilter::ExpiredOnly,
                },
            };
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            let options = ListOptions {
                profile,
                query,
                limit,
                after_id,
                view,
            };
            commands::list(
                &mut source,
                &options,
                &mut stdout().lock(),
                connection.format,
            )
            .await
        }
        Command::Get {
            connection,
            profile,
            id,
            visibility,
        } => {
            let view = visibility.view()?;
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            let mut selected = source.select_profiles(profile.as_deref())?;
            if selected.len() != 1 {
                bail!("The store has several profiles; choose one with --profile");
            }
            let profile = selected.remove(0);
            commands::get(
                &mut source,
                &profile,
                id,
                &view,
                &mut stdout().lock(),
                connection.format,
            )
            .await
        }
        Command::Changes { proposals, action } => changes_command(&proposals, action).await,
        Command::Serve {
            uri,
            pass_key_env,
            policy,
            agent_listen,
            token_file,
            proposals,
            review_command,
        } => {
            askar_explorer::agent::run(
                &uri,
                pass_key_env.as_deref(),
                policy.as_deref(),
                agent_listen,
                &token_file,
                &proposals,
                review_command,
            )
            .await
        }
        Command::Ui {
            uri,
            listen,
            allowed_hosts,
            idle_seconds,
            lockout_seconds,
        } => {
            askar_explorer::ui::run(
                &uri,
                askar_explorer::ui::Options {
                    listen,
                    allowed_hosts,
                    idle_timeout: std::time::Duration::from_secs(idle_seconds),
                    login_lockout: std::time::Duration::from_secs(lockout_seconds),
                },
            )
            .await
        }
        Command::Mcp {
            agent_url,
            token_file,
        } => {
            askar_explorer::mcp::run(&agent_url, askar_explorer::mcp::Token::File(token_file)).await
        }
        Command::Describe {
            connection,
            category,
            profile,
            sample,
            policy,
        } => {
            let policy = Policy::load(
                policy
                    .as_deref()
                    .unwrap_or_else(|| Path::new(".askar-explorer/policy.toml")),
            )?;
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            let options = DescribeOptions { profile, sample };
            let description =
                askar_explorer::describe::describe(&mut source, &category, &options, &policy)
                    .await?;
            commands::print_rows(
                description.columns,
                description.rows,
                &mut stdout().lock(),
                connection.format,
            )
        }
        Command::Sql {
            connection,
            query,
            visibility,
            limit,
        } => {
            let view = visibility.view()?;
            let source = Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            let source = Arc::new(tokio::sync::Mutex::new(source));
            let result = askar_explorer::sql::query(source, query, view, limit).await?;
            commands::print_rows(
                result.columns,
                result.rows,
                &mut stdout().lock(),
                connection.format,
            )?;
            if result.truncated {
                eprintln!("Output stopped at {limit} rows; raise --limit to see more.");
            }
            Ok(())
        }
        Command::Export {
            uri,
            out,
            include_kms,
            pass_key_env,
        } => askar_explorer::export(&uri, &out, include_kms, pass_key_env.as_deref()).await,
        Command::Apply {
            uri,
            edits,
            commit,
            pass_key_env,
            ..
        } => askar_explorer::apply::run(&uri, &edits, commit, pass_key_env.as_deref()).await,
    }
}

async fn changes_command(directory: &Path, action: ChangesAction) -> Result<()> {
    use askar_explorer::changes::{self, ApplyOptions, ProposalStore, Status};
    use std::io::{BufRead, IsTerminal, Write};

    let store = ProposalStore::new(directory);
    match action {
        ChangesAction::List => {
            let proposals = store.list()?;
            if proposals.is_empty() {
                println!("No proposals.");
            }
            for proposal in proposals {
                let status = format!("{:?}", proposal.status).to_lowercase();
                println!(
                    "{}  {:<9} {}  {}",
                    proposal.id, status, proposal.created_at, proposal.title
                );
            }
            Ok(())
        }
        ChangesAction::Show { id, connection } => {
            let mut source =
                Source::open(&connection.uri, connection.pass_key_env.as_deref()).await?;
            changes::review(&store, &id, &mut source, &mut stdout()).await?;
            Ok(())
        }
        ChangesAction::Apply {
            id,
            connection,
            write_uri,
            commit,
            confirm_backup,
        } => {
            let options = ApplyOptions {
                read_uri: &connection.uri,
                write_uri: write_uri.as_deref(),
                pass_key_env: connection.pass_key_env.as_deref(),
                commit,
                confirm_backup,
            };
            // A person must type the id: scripts and agents cannot answer this.
            let mut confirm = |id: &str| -> Result<bool> {
                if !std::io::stdin().is_terminal() {
                    bail!("Applying changes needs an interactive terminal (use docker compose exec without -T)");
                }
                eprint!("Type {id} to apply these changes: ");
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().lock().read_line(&mut answer)?;
                Ok(answer.trim() == id)
            };
            changes::apply_proposal(&store, &id, &options, &mut stdout(), &mut confirm).await?;
            Ok(())
        }
        ChangesAction::Reject { id } => {
            store.finish(&id, Status::Rejected)?;
            store.log(&format!("rejected {id}"))?;
            println!("Rejected {id}.");
            Ok(())
        }
    }
}
