use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    name = "casc",
    about = "Compile Cascade SELinux policies into CIL",
    long_about = "Compile Cascade SELinux policies into CIL.

The -o option to combine all policies and the -s option to build individual systems are mutually exclusive. See the OPTIONS section for more information on these options."
)]
pub struct Args {
    /// List of input files to process. Directories are searched recursively.
    #[clap(required(true))]
    pub input_file: Vec<String>,
    /// This is the default behavior.
    /// Combine all policies into a monolithic system policy with system configuration options set to default values.
    /// The generated CIL file is named OUT_FILENAME.
    #[clap(default_value = "out.cil", short, value_parser = clap::builder::ValueParser::new(parse_out_filename))]
    pub out_filename: String,
    /// Build the systems from the SYSTEM_NAMES list. "-s all" to build all defined systems.
    #[clap(short, conflicts_with = "out_filename")]
    pub system_names: Vec<String>,
    ///colorize the output.  WHEN can be 'always', 'auto' (default), or 'never'
    #[clap(long, value_enum, id = "WHEN")]
    pub color: Option<ColorArg>,
}

fn parse_out_filename(filename: &str) -> Result<String, String> {
    if filename.ends_with(".cil") {
        return Ok(filename.to_string());
    }
    Err(String::from("The value does not end in \".cil\""))
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ColorArg {
    Always,
    Auto,
    Never,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli() {
        Args::command().debug_assert();
    }
}
