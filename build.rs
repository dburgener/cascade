extern crate lalrpop;

use clap::CommandFactory;

#[path = "src/bin/casc/args.rs"]
mod casc;

fn main() -> std::io::Result<()> {
    // Generate parser
    lalrpop::process_src().unwrap();

    // Generate man page
    // https://rust-cli.github.io/book/in-depth/docs.html
    let out_dir =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or(std::io::ErrorKind::NotFound)?);
    let cmd = casc::Args::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;

    std::fs::write(out_dir.join("casc.1"), buffer)?;

    Ok(())
}
