use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, name = "casc", about = "Compile Cascade SELinux policies into CIL", long_about = None)]
pub struct Args {
    /// List of input files to process.  Directories are searched recursively.
    #[clap(required(true))]
    pub input_file: Vec<String>,
    #[clap(default_value = "out.cil", short)]
    pub out_filename: String,
}
