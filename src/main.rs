mod key_manager;
mod paillier_crypto;

use key_manager::keys;
use paillier_crypto::paillier_enc;

// cargo +nightly run
fn main() {
    let (enc_key, dec_key) = key_manager::keys();
    let cipher = paillier_enc(10, 15, 2, enc_key);

    println!("Decrypted: {}", paillier_crypto::paillier_dec(cipher, dec_key));
}

#[cfg(test)]
mod tests {

    use super::*;

    fn print_type_of<T>(_: &T) -> &'static str {
        return std::any::type_name::<T>();
    }

    fn init() -> (EncryptionKey, DecryptionKey, u64, u64, u64) {
        let (enc_key, dec_key) = key_manager::keys();

        let add1: u64 = 15;
        let add2: u64 = 22;
        let mul1: u64 = 10;

        return (enc_key, dec_key, add1, add2, mul1);
    }

    #[test]
    fn key_import_type_check() {
        let (enc_key, dec_key) = key_manager::keys();

        assert_eq!(print_type_of(&enc_key) == "paillier::EncryptionKey", true);
        assert_eq!(print_type_of(&dec_key) == "paillier::DecryptionKey", true);
    }

    #[test]
    fn paillier_enc_dec() {
        let (enc_key, dec_key, add1, add2, mul1) = init();

        let cipher: EncodedCiphertext<u64> = paillier_enc(add1, add2, mul1, enc_key);
        assert_eq!(paillier_dec(cipher, dec_key), (add1 + add2) * mul1);
    }
}
