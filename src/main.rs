use std::fs;
use std::io;

use cryptographic_message_syntax::{SignedData, SignerInfo};
use x509_certificate::certificate::CapturedX509Certificate;

fn main() {
    verify_jar("signed-jars/f-droid.org.jar", "CIARANG");
    verify_jar("signed-jars/apt.izzysoft.de.jar", "NEBO");
}

fn verify_jar(jar_file: &str, file_prefix: &str){
    println!("Verifying {}", jar_file);
    let file = fs::File::open(jar_file).unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    match zip::ZipArchive::new(file) {
        Ok(mut archive) => {
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).unwrap();
                let outpath = match file.enclosed_name() {
                    Some(path) => temp_dir.path().join(path.to_owned()),
                    None => continue,
                };
                if (&*file.name()).ends_with('/') {
                    fs::create_dir_all(&outpath).unwrap();
                } else {
                    if let Some(p) = outpath.parent() {
                        if !p.exists() {
                            fs::create_dir_all(&p).unwrap();
                        }
                    }
                    let mut outfile = fs::File::create(&outpath).unwrap();
                    io::copy(&mut file, &mut outfile).unwrap();
                }

                // Get and Set permissions
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;

                    if let Some(mode) = file.unix_mode() {
                    fs::set_permissions(&outpath, fs::Permissions::from_mode(mode)).unwrap();
                    }
                }
            }
        },
        Err(_) => {
            println!("F-Droid package index could not be extracted. Please try again.");
            std::process::exit(1);
        }
    }
    let bytes = fs::read(format!("{}/META-INF/{}.RSA", temp_dir.path().display(), file_prefix)).unwrap();
    let signed_data = SignedData::parse_ber(&bytes).unwrap();
    let cert = signed_data.certificates().collect::<Vec<&CapturedX509Certificate>>()[0].clone();
    let signer_info = signed_data.signers().collect::<Vec<&SignerInfo>>()[0].clone();
    let signed_file_data = fs::read(format!("{}/META-INF/{}.SF", temp_dir.path().display(), file_prefix)).unwrap();
    println!("{}", cert.verify_signed_data(signed_file_data.clone(), signer_info.signature()).is_ok());
}
