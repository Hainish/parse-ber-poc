use cryptographic_message_syntax::SignedData;
use std::fs;

fn main() {
    let ciarang_bytes = fs::read("rsa-files/CIARANG.RSA").unwrap();
    let one_bytes = fs::read("rsa-files/1.RSA").unwrap();
    assert!(SignedData::parse_ber(&ciarang_bytes).is_ok());
    assert!(SignedData::parse_ber(&one_bytes).is_ok());
}
