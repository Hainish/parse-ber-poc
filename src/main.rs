use std::fmt::Write;
use std::fs;

use cryptographic_message_syntax::SignedData;
use openssl::x509::X509;
use openssl::hash::MessageDigest;
use x509_certificate::certificate::CapturedX509Certificate;

fn main() {
    print_cert_fingerprint("rsa-files/CIARANG.RSA");
    print_cert_fingerprint("rsa-files/1.RSA");
}

fn print_cert_fingerprint(file: &str){
    let bytes = fs::read(file).unwrap();
    let cert = SignedData::parse_ber(&bytes).unwrap().certificates().collect::<Vec<&CapturedX509Certificate>>()[0].clone();
    let x509 = X509::from_der(&cert.encode_ber().unwrap()).unwrap();
    let cert_fingerprint = x509.digest(MessageDigest::from_name("sha256").unwrap()).unwrap();

    let mut s = String::new();
    for byte in cert_fingerprint.iter() {
        write!(&mut s, "{:02X?}", byte).expect("Unable to write");
    }
    println!("{}", s);
}
