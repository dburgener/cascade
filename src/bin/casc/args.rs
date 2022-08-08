use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, name = "casc", about = "Compile Cascade SELinux policies into CIL", long_about = None)]
pub struct Args {
    /// List of input files to process.  Directories are searched recursively.
    #[clap(required(true))]
    pub input_file: Vec<String>,
    #[clap(default_value = "out.cil", short, value_parser = clap::builder::ValueParser::new(parse_out_filename))]
    pub out_filename: String,
    #[clap(short, multiple_values = true, conflicts_with = "out-filename")]
    pub system_names: Vec<String>,
}

fn parse_out_filename(filename: &str) -> Result<String, String> {
    if filename.ends_with(".cil") {
        return Ok(filename.to_string());
    }
    Err(String::from("The value does not end in \".cil\""))
}
