use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use bgpkit_parser::BgpElem;

use monocle::database::{MonocleDatabase, RibSqliteStore};
use monocle::lens::rib::{RibLens, RibOutputType};
use monocle::utils::{OutputFormat, TimestampFormat};
use monocle::MonocleConfig;

use super::elem_format::{format_elem, format_elems_table, get_header};

pub use monocle::lens::rib::RibArgs;

const DEFAULT_FIELDS_RIB: &[&str] = &[
    "type",
    "timestamp",
    "peer_ip",
    "peer_asn",
    "prefix",
    "path_id",
    "as_path",
    "origin_asns",
    "origin",
    "next_hop",
    "local_pref",
    "med",
    "communities",
    "atomic",
    "aggr_asn",
    "aggr_ip",
    "collector",
];

pub fn run(config: &MonocleConfig, args: RibArgs, output_format: OutputFormat, no_update: bool) {
    if let Err(error) = run_inner(config, args, output_format, no_update) {
        eprintln!("ERROR: {}", error);
        std::process::exit(1);
    }
}

fn run_inner(
    config: &MonocleConfig,
    args: RibArgs,
    output_format: OutputFormat,
    no_update: bool,
) -> Result<()> {
    let sqlite_path = config.sqlite_path();
    let db = MonocleDatabase::open(&sqlite_path)
        .map_err(|e| anyhow!("Failed to open database '{}': {}", sqlite_path, e))?;
    let lens = RibLens::new(&db, config);

    match args.file_output_type() {
        None => run_stdout(&lens, &args, output_format, no_update),
        Some(RibOutputType::Sqlite) => run_sqlite_output(&lens, &args, no_update),
    }
}

fn run_stdout(
    lens: &RibLens<'_>,
    args: &RibArgs,
    output_format: OutputFormat,
    no_update: bool,
) -> Result<()> {
    let mut stdout = std::io::stdout();

    if output_format == OutputFormat::Table {
        let mut elems = Vec::<(BgpElem, Option<String>)>::new();
        lens.reconstruct_snapshots(args, no_update, |_rib_ts, state_store| {
            state_store.visit_entries(|entry| {
                elems.push((entry.elem, Some(entry.collector)));
                Ok(())
            })
        })?;

        if !elems.is_empty() {
            writeln!(
                stdout,
                "{}",
                format_elems_table(&elems, DEFAULT_FIELDS_RIB, TimestampFormat::Unix)
            )
            .map_err(|e| anyhow!("Failed to write table output: {}", e))?;
        }
        return Ok(());
    }

    let mut header_written = false;
    lens.reconstruct_snapshots(args, no_update, |_rib_ts, state_store| {
        if !header_written {
            if let Some(header) = get_header(output_format, DEFAULT_FIELDS_RIB) {
                writeln!(stdout, "{}", header)
                    .map_err(|e| anyhow!("Failed to write output header: {}", e))?;
            }
            header_written = true;
        }

        state_store.visit_entries(|entry| {
            if let Some(line) = format_elem(
                &entry.elem,
                output_format,
                DEFAULT_FIELDS_RIB,
                Some(entry.collector.as_str()),
                TimestampFormat::Unix,
            ) {
                writeln!(stdout, "{}", line)
                    .map_err(|e| anyhow!("Failed to write reconstructed RIB row: {}", e))?;
            }
            Ok(())
        })
    })?;

    Ok(())
}

fn run_sqlite_output(lens: &RibLens<'_>, args: &RibArgs, no_update: bool) -> Result<()> {
    let normalized_ts = args.validate()?;
    let output_dir = ensure_output_dir(lens.output_directory(args)?)?;
    let output_path = output_dir.join(format!(
        "{}.sqlite3",
        lens.file_name_prefix(args, &normalized_ts)?
    ));

    remove_existing_file(&output_path)?;

    let sqlite_store = RibSqliteStore::new(path_to_str(&output_path)?, true)?;
    let summary = lens.reconstruct_snapshots(args, no_update, |rib_ts, state_store| {
        state_store.visit_entries(|entry| sqlite_store.insert_entry(rib_ts, &entry))
    })?;

    eprintln!(
        "wrote {} reconstructed RIB snapshot(s) to {}",
        summary.rib_ts.len(),
        output_path.display()
    );
    Ok(())
}

fn ensure_output_dir(path: Option<PathBuf>) -> Result<PathBuf> {
    let output_dir = path.ok_or_else(|| anyhow!("Failed to resolve output directory"))?;
    fs::create_dir_all(&output_dir).map_err(|e| {
        anyhow!(
            "Failed to create output directory '{}': {}",
            output_dir.display(),
            e
        )
    })?;
    Ok(output_dir)
}

fn remove_existing_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow!(
            "Failed to remove existing output file '{}': {}",
            path.display(),
            error
        )),
    }
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("Path '{}' contains invalid UTF-8", path.display()))
}
