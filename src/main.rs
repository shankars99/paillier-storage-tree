extern crate paillier;
use paillier::*;

// cargo +nightly run
fn main() {
    let (enc_key, dec_key) = Paillier::keypair().keys();
}

fn paillier_enc(add1: u64, add2: u64, mul1: u64, enc_key: EncryptionKey) -> EncodedCiphertext<u64> {
    let c1 = Paillier::encrypt(&enc_key, add1);
    let c2 = Paillier::encrypt(&enc_key, add2);

    let c = Paillier::add(&enc_key, &c1, &c2);

    let d = Paillier::mul(&enc_key, &c, mul1);
    d
}

fn paillier_dec(d: EncodedCiphertext<u64>, dec_key: DecryptionKey) -> u64 {
    let m: u64 = Paillier::decrypt(&dec_key, &d);
    m
}

// write a test
#[cfg(test)]
mod tests {
    use super::*;

    fn init() -> (EncryptionKey, DecryptionKey, u64, u64, u64){
        let (enc_key, dec_key) = Paillier::keypair().keys();
        let add1: u64 = 15;
        let add2: u64 = 22;
        let mul1: u64 = 10;

        return (enc_key, dec_key, add1, add2, mul1);
    }

    #[test]
    fn test_paillier() {
        let (enc_key, dec_key, add1, add2, mul1) = init();

        let cipher: EncodedCiphertext<u64> = paillier_enc(add1, add2, mul1, enc_key);
        assert_eq!(paillier_dec(cipher, dec_key), (add1 + add2) * mul1);
    }
}
