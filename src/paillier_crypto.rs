extern crate paillier;
use paillier::*;

pub fn paillier_enc(add1: u64, add2: u64, mul1: u64, enc_key: EncryptionKey) -> EncodedCiphertext<u64> {
    let c1 = Paillier::encrypt(&enc_key, add1);
    let c2 = Paillier::encrypt(&enc_key, add2);

    let c = Paillier::add(&enc_key, &c1, &c2);

    let d = Paillier::mul(&enc_key, &c, mul1);
    d
}

pub fn paillier_dec(d: EncodedCiphertext<u64>, dec_key: DecryptionKey) -> u64 {
    let m: u64 = Paillier::decrypt(&dec_key, &d);
    m
}
