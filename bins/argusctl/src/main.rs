use clap::{Parser, Subcommand};

/// argusctl — CLI management tool for Argus IAM
#[derive(Parser)]
#[command(name = "argusctl", version, about, long_about = None)]
struct Cli {
    /// Server URL to connect to
    #[arg(long, default_value = "http://localhost:8080", global = true)]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check server health status
    Health,
    /// Show server configuration (requires admin access)
    Config,
    /// Manage signing keys
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Display JWKS public keys
    Jwks,
}

#[derive(Subcommand)]
enum KeysAction {
    /// List active and retired signing keys
    List,
    /// Trigger key rotation
    Rotate,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Health => {
            let url = format!("{}/health", cli.server);
            match reqwest::get(&url).await {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    if status.is_success() {
                        println!("{body}");
                    } else {
                        eprintln!("server returned {status}: {body}");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("failed to connect to {url}: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Jwks => {
            let url = format!("{}/.well-known/jwks.json", cli.server);
            match reqwest::get(&url).await {
                Ok(resp) => {
                    let body = resp.text().await.unwrap_or_default();
                    // Pretty-print the JSON
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                        println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    } else {
                        println!("{body}");
                    }
                }
                Err(e) => {
                    eprintln!("failed to fetch JWKS: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Config => {
            println!("config inspection not yet available (requires admin API — Phase 1)");
        }
        Commands::Keys { action } => match action {
            KeysAction::List => {
                println!("key listing not yet available (requires admin API — Phase 1)");
            }
            KeysAction::Rotate => {
                println!("key rotation not yet available (requires admin API — Phase 1)");
            }
        },
    }
}
