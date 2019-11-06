use base64::decode_config_slice;
use ed25519_dalek::{verify_batch, PublicKey, Signature};
use regex::bytes::Regex;
use sha2::Sha512;
use ssb_legacy_msg_data::json::{from_slice, to_string};
use ssb_legacy_msg_data::value::Value;
use std::borrow::Cow;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    /// This is an example for using doc comment attributes
    static ref SIGNATURE_REGEX: Regex = Regex::new(r##"(,\n\s+"signature":\s".+.ed25519")"##).unwrap();
    static ref SIGNATURE_BYTES_REGEX: Regex = Regex::new(r##"\n\s+"signature":\s"(.+).sig.ed25519""##).unwrap();
    static ref PUBKEY_BYTES_REGEX: Regex = Regex::new(r##"\n\s+"author":\s"@(.+).ed25519""##).unwrap();
}

pub fn verify(msg: &[u8]) -> bool {
    let (key, sig, bytes) = get_pubkey_sig_bytes_from_ssb_message(msg);
    key.verify::<Sha512>(&bytes, &sig).is_ok()
}

fn get_pubkey_sig_bytes_from_ssb_message<'a>(msg: &'a [u8]) -> (PublicKey, Signature, Vec<u8>) {
    // Parse the signature string
    let sig_bytes = get_sig_bytes(msg);
    // Parse the author string
    let key_bytes = get_key_bytes(msg);

    // Convert the signature bytes to a dalek signature
    let key = PublicKey::from_bytes(&key_bytes).unwrap();

    // Convert the author bytes to a dalek pub key
    let sig = Signature::from_bytes(&sig_bytes).unwrap();

    let value = extract_value_from_entry(msg);
    // Remove the signature
    let bytes_to_verify = remove_signature_from_entry(value.as_bytes());

    (key, sig, bytes_to_verify.to_vec())
}

fn get_sig_bytes<'a>(msg: &'a [u8]) -> [u8; 64] {
    let caps = SIGNATURE_BYTES_REGEX.captures(msg).unwrap();
    let sig_str = caps.get(1).unwrap();
    let mut buff = [0; 64];
    decode_config_slice(sig_str.as_bytes(), base64::STANDARD, &mut buff).unwrap();
    buff
}

fn get_key_bytes<'a>(msg: &'a [u8]) -> [u8; 32] {
    let caps = PUBKEY_BYTES_REGEX.captures(msg).unwrap();
    let key_str = caps.get(1).unwrap();
    let mut buff = [0; 32];
    decode_config_slice(key_str.as_bytes(), base64::STANDARD, &mut buff).unwrap();
    buff
}

fn remove_signature_from_entry<'a>(msg: &'a [u8]) -> Cow<'a, [u8]> {
    SIGNATURE_REGEX.replace_all(msg, &b""[..])
}

fn extract_value_from_entry<'a>(msg: &'a [u8]) -> String {
    let val: Value = from_slice(&msg).unwrap();

    let value = match val {
        Value::Object(ref o) => o.get("value").unwrap(),
        _ => panic!(),
    };
    to_string(value, false).unwrap()
}

#[cfg(test)]
mod tests {

    use crate::{
        extract_value_from_entry, get_key_bytes, get_sig_bytes, remove_signature_from_entry, verify,
    };
    use base64;

    #[test]
    fn it_works() {
        let msg = VALID_MESSAGE.as_bytes();
        assert!(verify(&msg));
    }

    #[test]
    fn get_sig_bytes_works() {
        let expected = base64::decode("PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==").unwrap();
        let bytes = get_sig_bytes(VALID_MESSAGE.as_bytes());
        assert_eq!(&bytes[..], &expected[..]);
    }
    #[test]
    fn get_key_bytes_works() {
        let expected = base64::decode("U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=").unwrap();
        let bytes = get_key_bytes(VALID_MESSAGE.as_bytes());
        assert_eq!(&bytes[..], &expected[..]);
    }

    #[test]
    fn remove_signature_from_entry_works() {
        let msg = VALID_ENTRY.as_bytes();
        let result = remove_signature_from_entry(&msg);
        assert_eq!(result, VALID_ENTRY_NO_SIGNATURE.as_bytes());
    }

    #[test]
    fn extract_value_from_entry_works() {
        let msg = VALID_MESSAGE.as_bytes();
        let result = extract_value_from_entry(&msg);

        assert_eq!(&result, VALID_ENTRY);
    }
    const VALID_MESSAGE: &str = r##"{
  "key": "%kmXb3MXtBJaNugcEL/Q7G40DgcAkMNTj3yhmxKHjfCM=.sha256",
  "value": {
    "previous": "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 8,
    "timestamp": 1470187438539,
    "hash": "sha256",
    "content": {
      "type": "contact",
      "contact": "@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519",
      "following": true,
      "blocking": false
    },
    "signature": "PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519"
  },
  "timestamp": 1571140551543
}"##;

    const VALID_ENTRY: &str = r##"{
  "previous": "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
  "sequence": 8,
  "timestamp": 1470187438539,
  "hash": "sha256",
  "content": {
    "type": "contact",
    "contact": "@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519",
    "following": true,
    "blocking": false
  },
  "signature": "PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519"
}"##;

    const VALID_ENTRY_NO_SIGNATURE: &str = r##"{
  "previous": "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
  "sequence": 8,
  "timestamp": 1470187438539,
  "hash": "sha256",
  "content": {
    "type": "contact",
    "contact": "@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519",
    "following": true,
    "blocking": false
  }
}"##;
}
