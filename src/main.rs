use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

/// Generate Protocol Buffer definitions from OCSF JSON schema.
///
/// Downloads the OCSF schema export from schema.ocsf.io and generates
/// deterministic .proto files for selected event classes and their
/// transitive object dependencies.
#[derive(Parser)]
#[command(name = "ocsf-proto-gen", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download the OCSF schema export and cache locally.
    #[cfg(feature = "download")]
    DownloadSchema {
        /// OCSF version to download (e.g., "1.7.0").
        #[arg(long, default_value = "1.7.0")]
        ocsf_version: String,

        /// Output directory for cached schema.
        #[arg(long, default_value = ".")]
        output_dir: PathBuf,

        /// Base URL for the OCSF schema export API.
        #[arg(
            long,
            default_value = "https://schema.ocsf.io/export/v2/schema",
            env = "OCSF_SCHEMA_URL"
        )]
        schema_url: String,
    },

    /// Generate .proto files from a cached OCSF schema.
    Generate {
        /// OCSF version to generate for.
        #[arg(long, default_value = "1.7.0")]
        ocsf_version: String,

        /// Comma-separated event class names, or "all" for every class.
        ///
        /// Example: --classes authentication,security_finding,network_activity
        #[arg(long)]
        classes: String,

        /// Output directory for generated .proto files.
        #[arg(long, default_value = ".")]
        output_dir: PathBuf,

        /// Directory containing cached schema files.
        /// Schema is expected at <schema-dir>/<version>/schema.json.
        #[arg(long, default_value = ".")]
        schema_dir: PathBuf,

        /// Comma-separated list of field names that should ONLY belong to BaseEvent.
        /// All other base fields will be generated in specific event classes.
        #[arg(long)]
        custom_base_fields: Option<String>,

        /// Suppress non-error output.
        #[arg(long, short)]
        quiet: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {e}");

        // Print cause chain.
        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            eprintln!("  caused by: {cause}");
            source = std::error::Error::source(cause);
        }

        process::exit(1);
    }
}

fn run(cli: Cli) -> ocsf_proto_gen::error::Result<()> {
    match cli.command {
        #[cfg(feature = "download")]
        Commands::DownloadSchema {
            ocsf_version,
            output_dir,
            schema_url,
        } => {
            let path = output_dir.join(&ocsf_version).join("schema.json");
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| ocsf_proto_gen::error::Error::Schema(e.to_string()))?;
            rt.block_on(ocsf_proto_gen::schema::download_schema(
                &ocsf_version,
                &path,
                &schema_url,
            ))?;
        }

        Commands::Generate {
            ocsf_version,
            classes,
            output_dir,
            schema_dir,
            custom_base_fields,
            quiet,
        } => {
            let schema_path = schema_dir.join(&ocsf_version).join("schema.json");
            if !quiet {
                eprintln!("Loading schema from {}", schema_path.display());
            }
            let schema = ocsf_proto_gen::schema::load_schema(&schema_path)?;
            if !quiet {
                eprintln!(
                    "Loaded OCSF v{}: {} classes, {} objects",
                    schema.version,
                    schema.classes.len(),
                    schema.objects.len()
                );
            }

            let class_names: Vec<String> = if classes == "all" {
                schema.classes.keys().cloned().collect()
            } else {
                classes
                    .split(',')
                    .map(|s| s.trim())
                    .map(|s| {
                        if let Ok(uid) = s.parse::<u32>() {
                            if let Some(c) = schema.classes.values().find(|c| c.uid == uid) {
                                return c.name.clone();
                            }
                        }
                        s.to_string()
                    })
                    .collect()
            };

            if !quiet {
                eprintln!("Generating protos for {} classes", class_names.len());
            }

            let custom_base_fields = custom_base_fields.map(|s| {
                s.split(',')
                    .map(|f| f.trim().to_string())
                    .collect::<Vec<String>>()
            });

            let stats = ocsf_proto_gen::codegen::generate(
                &schema, 
                &class_names, 
                &output_dir,
                custom_base_fields,
            )?;

            if !quiet {
                eprintln!(
                    "Generated {} classes, {} objects, {} enums",
                    stats.classes_generated, stats.objects_generated, stats.enums_generated
                );
                if stats.deprecated_fields_skipped > 0 {
                    eprintln!(
                        "Skipped {} deprecated fields",
                        stats.deprecated_fields_skipped
                    );
                }
                if stats.string_enum_fields_skipped > 0 {
                    eprintln!(
                        "Skipped {} string-keyed enums (not valid proto enums)",
                        stats.string_enum_fields_skipped
                    );
                }
                if stats.unknown_types_defaulted > 0 {
                    eprintln!(
                        "Defaulted {} unknown types to string",
                        stats.unknown_types_defaulted
                    );
                }
                eprintln!("Done.");
            }
        }
    }

    Ok(())
}
