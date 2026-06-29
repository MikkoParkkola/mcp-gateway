use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum TrustCommand {
    #[command(about = "Inspect a backend's TrustCard")]
    Inspect {
        #[arg(required = true)]
        backend: String,
        #[arg(short, long, default_value = "gateway.yaml")]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Generate TrustCard and CBOM for a backend")]
    Generate {
        #[arg(required = true)]
        backend: String,
        #[arg(short, long, default_value = "gateway.yaml")]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Validate a TrustCard or CBOM")]
    Validate {
        #[arg(required = true)]
        backend: String,
        #[arg(short, long, default_value = "gateway.yaml")]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
}
