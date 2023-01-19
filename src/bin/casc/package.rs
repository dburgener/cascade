use std::convert::TryInto;
///Make a full set of policy files, as stored in /etc/selinux
use std::fs;
use std::io::{Error, ErrorKind, Write};
use std::path::Path;
use std::process::Command;

use flate2::write::GzEncoder;
use flate2::Compression;
use tar::{Builder, Header};

use selinux_cascade::{generate_dbus_contexts, generate_seusers};

const FC_NAME: &str = "file_contexts";

/// Assumes system_name.cil has already been created by prior functions
pub fn build_package(
    system_name: &str,
    cil_path: &str,
    policy_binary_version: &str,
) -> std::io::Result<()> {
    let policy_name = ["policy.", policy_binary_version].concat();
    let tar_gz = fs::File::create("selinux_policy.tar.gz")?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = tar::Builder::new(enc);

    let output = Command::new("secilc")
        .arg(["--policyvers=", policy_binary_version].concat())
        .arg(cil_path)
        .output()?;
    if !output.status.success() {
        if let Ok(stderr) = std::str::from_utf8(&output.stderr) {
            eprintln!("{}", stderr);
        }
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Compliation of generated CIL failed with message.  This is a Cascade bug",
        ));
    }
    add_file_to_tar(
        &mut tar,
        system_name,
        &["policy/", &policy_name].concat(),
        &policy_name,
    )?;
    add_file_to_tar(
        &mut tar,
        system_name,
        "contexts/files/file_contexts",
        FC_NAME,
    )?;
    let dbus_contexts = match generate_dbus_contexts() {
        Ok(contexts) => contexts,
        Err(e) => {
            eprintln!("Failed generating dbus_contexts file: {}", e);
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Generation of dbus_contexts failed.  This is a Cascade bug",
            ));
        }
    };
    add_file_to_tar_from_string(
        &mut tar,
        system_name,
        "contexts/dbus_contexts",
        &dbus_contexts,
    )?;
    add_file_to_tar_from_string(&mut tar, system_name, "seusers", &generate_seusers())?;
    tar.finish()
}

fn add_file_to_tar<W>(
    tar: &mut Builder<W>,
    system_name: &str,
    target_path: &str,
    file_path: &str,
) -> std::io::Result<()>
where
    W: Write,
{
    let mut fd = fs::File::open(file_path)?;
    let out_path = Path::new(system_name).join(target_path);
    tar.append_file(out_path, &mut fd)
}

fn add_file_to_tar_from_string<W>(
    tar: &mut Builder<W>,
    system_name: &str,
    target_path: &str,
    file_contents: &str,
) -> std::io::Result<()>
where
    W: Write,
{
    let mut header = Header::new_gnu();
    header.set_size(file_contents.len().try_into().unwrap()); //TODO: handle error
    header.set_mode(0o644);
    header.set_cksum();
    let out_path = Path::new(system_name).join(target_path);
    tar.append_data(&mut header, out_path, file_contents.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use tar::Archive;

    #[test]
    fn test_package() {
        for version in ["30", "31", "32"] {
            build_package("foo", "data/expected_cil/simple.cil", version).unwrap();
            if !Path::new("package_test").exists() {
                fs::create_dir("package_test").unwrap();
            }
            let tar_gz = fs::File::open("selinux_policy.tar.gz").unwrap();
            let tar = GzDecoder::new(tar_gz);
            let mut archive = Archive::new(tar);
            archive.unpack("package_test").unwrap();

            for file in [
                &["policy/policy.", version].concat(),
                "contexts/files/file_contexts",
                "contexts/dbus_contexts",
            ] {
                let filename = &["package_test/foo/", file].concat();
                let metadata = fs::metadata(filename).unwrap();
                assert!(metadata.is_file());
            }

            fs::remove_dir_all("package_test").unwrap();
        }
    }
}
