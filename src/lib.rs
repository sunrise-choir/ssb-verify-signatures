use arrayvec::ArrayVec;
use base64::decode_config_slice;
use ed25519_dalek::{verify_batch as dalek_verify_batch, PublicKey, Signature};
use rayon::prelude::*;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Error as SerdeJsonError;
use sha2::Sha512;
use snafu::{OptionExt, ResultExt, Snafu};
use ssb_legacy_msg_data::json::{from_slice, to_string, DecodeJsonError, EncodeJsonError};
use ssb_legacy_msg_data::value::Value;

#[macro_use]
extern crate lazy_static;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Signature string could not be parsed into a valid ed25519 sig"))]
    InvalidSignatureBytes,
    #[snafu(display("Key string could not be parsed into a valid ed25519 sig"))]
    InvalidKeyBytes,
    #[snafu(display("Signature was invalid"))]
    InvalidSignature {},
    #[snafu(display("Error parsing ssb message, it is invalid. Errored with: {}", source))]
    InvalidSsbMessage { source: DecodeJsonError },
    #[snafu(display("Error encoding ssb message, it is invalid. Errored with: {}", source))]
    UnableToEncodeMessageToValidSigningEncoding { source: EncodeJsonError },
    #[snafu(display(
        "Error parsing ssb message as json, it is invalid. Errored with: {}",
        source
    ))]
    InvalidSsbMessageJson { source: SerdeJsonError },
    #[snafu(display("The signature was not a valid ssb ed25519 signature string."))]
    InvalidSignatureString {},
    #[snafu(display("The signature was not valid base64 encoding. {}", source))]
    InvalidSignatureStringBase64Encoding { source: base64::DecodeError },
    #[snafu(display("The author pub key was not a valid ssb ed25519 pub key string."))]
    InvalidAuthorString {},
    #[snafu(display("The author pub key was not valid base64 encoding. {}", source))]
    InvalidAuthorStringBase64Encoding { source: base64::DecodeError },
    #[snafu(display("Unable to get the value from the message, the message was invalid"))]
    InvalidMessageNoValue,
}

type Result<T, E = Error> = std::result::Result<T, E>;
type KeySigBytes = (PublicKey, Signature, Vec<u8>);

#[derive(Serialize, Deserialize, Debug)]
struct SsbMessageValue<'a> {
    signature: &'a str,
    author: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
struct SsbMessage<'a> {
    #[serde(borrow)]
    value: SsbMessageValue<'a>,
}

lazy_static! {
    static ref SIGNATURE_BYTES_REGEX: Regex =
        Regex::new(r##"([A-Za-z0-9\\/+]{86}==).sig.ed25519"##).unwrap();
    static ref PUBKEY_BYTES_REGEX: Regex =
        Regex::new(r##"@([A-Za-z0-9\\/+]{43}=).ed25519"##).unwrap();
}

pub fn verify(msg: &[u8]) -> Result<()> {
    let (key, sig, bytes) = get_pubkey_sig_bytes_from_ssb_message(msg)?;
    key.verify::<Sha512>(&bytes, &sig)
        .map_err(|_| snafu::NoneError)
        .context(InvalidSignature)
}

pub fn par_verify(msgs: &[&[u8]]) -> Result<()> {
    // Ok, I know this looks weird. But we want to be able to try and verify all msgs but abort
    // with Error when we hit something that did not verify.
    msgs.par_iter()
        .try_fold(|| (), |_, msg| verify(msg))
        .try_reduce(|| (), |_, _| Ok(()))
}

const CHUNK_SIZE: usize = 50;

pub fn par_verify_batch(msgs: &[&[u8]]) -> Result<()> {
    msgs.par_iter()
        .chunks(CHUNK_SIZE)
        .try_fold(
            || (),
            |_, chunk| {
                let keys_sigs_bytes = chunk.iter()
                    .flat_map(|msg| get_pubkey_sig_bytes_from_ssb_message(msg))
                    .collect::<ArrayVec<[KeySigBytes; CHUNK_SIZE]>>();
                //each chunk is a collection of (key, sig, bytes)
                let keys = keys_sigs_bytes
                    .iter()
                    .map(|(key, _, _)| *key)
                    .collect::<ArrayVec<[_; CHUNK_SIZE]>>();
                let sigs = keys_sigs_bytes
                    .iter()
                    .map(|(_, sig, _)| *sig)
                    .collect::<ArrayVec<[_; CHUNK_SIZE]>>();
                let bytes = keys_sigs_bytes
                    .iter()
                    .map(|(_, _, msg)| msg.as_slice())
                    .collect::<ArrayVec<[_; CHUNK_SIZE]>>();

                dalek_verify_batch::<Sha512>(bytes.as_slice(), sigs.as_slice(), keys.as_slice())
                    .map_err(|_| snafu::NoneError)
                    .context(InvalidSignature)
            },
        )
        .try_reduce(|| (), |_, _| Ok(()))
}

fn get_pubkey_sig_bytes_from_ssb_message<'a>(
    msg: &'a [u8],
) -> Result<KeySigBytes> {
    let mut verifiable_msg: Value = from_slice(&msg).context(InvalidSsbMessage)?;
    let message: SsbMessage = serde_json::from_slice(msg).context(InvalidSsbMessageJson)?;

    // Parse the signature string
    let sig_bytes = get_sig_bytes(message.value.signature.as_bytes())?;
    // Parse the author string
    let key_bytes = get_key_bytes(message.value.author.as_bytes())?;

    // Convert the signature bytes to a dalek signature
    let key = PublicKey::from_bytes(&key_bytes)
        .map_err(|_| snafu::NoneError)
        .context(InvalidKeyBytes)?;

    // Convert the author bytes to a dalek pub key
    let sig = Signature::from_bytes(&sig_bytes)
        .map_err(|_| snafu::NoneError)
        .context(InvalidSignatureBytes)?;

    // Modify the val by removing the signature
    if let Value::Object(ref mut msg) = verifiable_msg {
        if let Some(Value::Object(ref mut v)) = msg.get_mut("value") {
            v.remove("signature".to_owned());
        }
    };

    // Get the value from the message as this is what was signed
    let verifiable_msg_value = match verifiable_msg {
        Value::Object(ref mut o) => o.get("value").context(InvalidMessageNoValue)?,
        _ => panic!(),
    };

    // Encode the message to a string with out the signature. This was how it was when it was
    // signed by the author.
    let bytes_to_verify = to_string(&verifiable_msg_value, false)
        .context(UnableToEncodeMessageToValidSigningEncoding)?;

    Ok((key, sig, bytes_to_verify.into_bytes()))
}

fn get_sig_bytes<'a>(sig: &'a [u8]) -> Result<[u8; 64]> {
    let caps = SIGNATURE_BYTES_REGEX
        .captures(sig)
        .context(InvalidSignatureString)?;
    let sig_str = caps.get(1).context(InvalidSignatureString)?;
    let mut buff = [0; 64];
    decode_config_slice(sig_str.as_bytes(), base64::STANDARD, &mut buff)
        .context(InvalidSignatureStringBase64Encoding)?;
    Ok(buff)
}

fn get_key_bytes<'a>(key: &'a [u8]) -> Result<[u8; 32]> {
    let caps = PUBKEY_BYTES_REGEX
        .captures(key)
        .context(InvalidAuthorString)?;
    let key_str = caps.get(1).context(InvalidAuthorString)?;
    let mut buff = [0; 32];
    decode_config_slice(key_str.as_bytes(), base64::STANDARD, &mut buff)
        .context(InvalidAuthorStringBase64Encoding)?;
    Ok(buff)
}

#[cfg(test)]
mod tests {

    use crate::{get_key_bytes, get_sig_bytes, verify};
    use base64;

    #[test]
    fn it_works() {
        let msg = VALID_MESSAGE.as_bytes();
        assert!(verify(&msg).is_ok());
    }

    #[test]
    fn get_sig_bytes_works() {
        let expected = base64::decode("PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==").unwrap();
        let bytes = get_sig_bytes("PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519".as_bytes()).unwrap();
        assert_eq!(&bytes[..], &expected[..]);
    }

    #[test]
    fn get_key_bytes_works() {
        let expected = base64::decode("U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=").unwrap();
        let bytes =
            get_key_bytes("@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519".as_bytes())
                .unwrap();
        assert_eq!(&bytes[..], &expected[..]);
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
}
