extern crate paillier;
use paillier::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::prelude::*;

pub fn keys() -> (EncryptionKey, DecryptionKey) {
    let (enc_key, dec_key) = Paillier::keypair().keys();

    let serial_enc_key: String =
        fs::read_to_string("./data/enc_key.key").expect("Unable to read file");
    let serial_dec_key: String = fs::read_to_string("./data/dec_key.key").expect("Unable to read file");

    if serial_enc_key.len() == 0 || serial_dec_key.len() == 0 {
        let serial_enc_key: String = serde_json::to_string(&enc_key).unwrap();
        let serial_dec_key: String = serde_json::to_string(&dec_key).unwrap();

        fs::write("./data/enc_key.key", serial_enc_key).expect("Unable to write file");
        fs::write("./data/dec_key.key", serial_dec_key).expect("Unable to write file");
    } else {
        let enc_key: EncryptionKey = serde_json::from_str(&serial_enc_key).unwrap();
        let dec_key: DecryptionKey = serde_json::from_str(&serial_dec_key).unwrap();
    }

    (enc_key, dec_key)
}
