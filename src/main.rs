//! `rustrip` CLI: parse a (possibly stripped + format-stripped) binary,
//! run the analyzer pipeline, and render annotations in a chosen format.

use anyhow::{Context, Result};
use clap::Parser;
use std::io::{Read, Write};
use std::path::PathBuf;

use rustrip::analyzers::{
    panics::PanicsAnalyzer, strings::StringsAnalyzer, symbols::SymbolsAnalyzer, Registry,
};
use rustrip::output::{
    binja::Binja, ghidra::Ghidra, json::Json, table::Table, Format, OutputBackend,
};

#[derive(Parser, Debug)]
#[command(
    name = "rustrip",
    version,
    about = "Make stripped Rust binaries readable again",
    long_about = "rustrip recovers `&str` slice boundaries, demangles Rust symbols, \
                  and reconstructs panic site source locations from release/stripped \
                  ELF, PE, and Mach-O binaries. Outputs to a table, JSON, or a Ghidra/\
                  Binary Ninja Python script that re-applies annotations."
)]
struct Cli {
    /// Path to the binary to analyze. Use `-` to read from stdin.
    path: PathBuf,

    /// Output format: table (default), json, ghidra, binja.
    #[arg(long, short = 'f', default_value = "table")]
    format: String,

    /// Write to file instead of stdout. Scripts (`ghidra`, `binja`) almost
    /// always want this.
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Skip the string-slice analyzer.
    #[arg(long)]
    no_strings: bool,

    /// Skip the symbol-demangling analyzer.
    #[arg(long)]
    no_symbols: bool,

    /// Skip the panic-location analyzer.
    #[arg(long)]
    no_panics: bool,

    /// Maximum length of a recovered &str. Default: 4096 bytes.
    #[arg(long, default_value_t = 4096)]
    max_string_len: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let bytes = read_bytes(&cli.path)?;

    let bin = rustrip::binary::Binary::parse(cli.path.to_str(), bytes).context("loading binary")?;

    let mut registry = Registry::new();
    if !cli.no_strings {
        let lim = rustrip::analyzers::Limits {
            max_string_len: cli.max_string_len,
            ..rustrip::analyzers::Limits::default()
        };
        registry = registry.with(Box::new(StringsAnalyzer::with_limits(lim)));
    }
    if !cli.no_symbols {
        registry = registry.with(Box::new(SymbolsAnalyzer::new()));
    }
    if !cli.no_panics {
        registry = registry.with(Box::new(PanicsAnalyzer::new()));
    }
    let anns = registry.run(&bin);

    let fmt =
        Format::parse(&cli.format).with_context(|| format!("unknown --format '{}'", cli.format))?;

    let backend: Box<dyn OutputBackend> = match fmt {
        Format::Table => Box::new(Table),
        Format::Json => Box::new(Json),
        Format::GhidraScript => Box::new(Ghidra),
        Format::BinjaScript => Box::new(Binja),
    };

    let mut sink: Box<dyn Write> = match cli.output.as_ref() {
        Some(p) => {
            Box::new(std::fs::File::create(p).with_context(|| format!("creating {}", p.display()))?)
        }
        None => Box::new(std::io::stdout().lock()),
    };

    backend.render(&anns, &mut *sink)?;
    Ok(())
}

fn read_bytes(path: &PathBuf) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if path.to_str() == Some("-") {
        std::io::stdin().read_to_end(&mut buf)?;
    } else {
        let mut f =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        f.read_to_end(&mut buf)?;

        // If the path looks like a Windows shortcut to an underlying binary
        // (e.g. ".exe" but really an ELF — accidental cross-build), fail
        // loudly rather than producing an empty analysis.
        if buf.len() < 4 {
            anyhow::bail!("binary too small: {} bytes", buf.len());
        }
    }
    Ok(buf)
}
