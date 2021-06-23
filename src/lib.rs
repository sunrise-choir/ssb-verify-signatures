//! Verify Secure Scuttlebutt message signatures (in parallel)
//!
//! # How is this different to [ssb-legacy-msg](https://github.com/sunrise-choir/ssb-legacy-msg)?
//!
//! It's built on top of `ssb-legacy-msg` and `ssb-legacy-msg-data` but exposed a hopefully easier
//! api, and most importantly it lets you _batch process_ a collection of messages.
//!
//! Batch processing is good for two reasons:
//! - it means we can utilise multiple cores using [rayon](https://docs.rs/rayon/1.2.0/rayon/index.html)
//! - it means we can use the [ed25519_dalek verify_batch](https://docs.rs/ed25519-dalek/0.9.1/ed25519_dalek/fn.verify_batch.html) function that takes advantage of
//! processor SIMD instuctions.
//!
//! Benchmarking on a 2016 2 core i5 shows that batch processing with [par_verify_messages] is ~3.6 times faster than using [verify_message]
//!
//! Benchmarking on Android on a [One Plus 5T](https://en.wikipedia.org/wiki/OnePlus_5T) (8 core arm64) shows that batch processing with [par_verify_messages] is ~9.9 times faster than using [verify_message]!
//!
use arrayvec::ArrayVec;
use base64::decode_config_slice;
use rayon::prelude::*;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeJsonError;
use snafu::{OptionExt, ResultExt, Snafu};
use ssb_crypto::{AsBytes, NetworkKey};
use ssb_legacy_msg_data::json::{from_slice, to_string, DecodeJsonError, EncodeJsonError};
use ssb_legacy_msg_data::value::Value;

use ed25519_dalek::{verify_batch as dalek_verify_batch, PublicKey, Signature, Verifier};

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
    #[snafu(display("The length of the hmac key was not 32 bytes."))]
    InvalidHmac,
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

/// Verify the signature of an entire ssb message that has `key` and `value`.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {}}`
///
/// # Example
///```
///use ssb_verify_signatures::verify_message;
///let valid_message = r##"{
///  "key": "%kmXb3MXtBJaNugcEL/Q7G40DgcAkMNTj3yhmxKHjfCM=.sha256",
///  "value": {
///    "previous": "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
///    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "sequence": 8,
///    "timestamp": 1470187438539,
///    "hash": "sha256",
///    "content": {
///      "type": "contact",
///      "contact": "@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519",
///      "following": true,
///      "blocking": false
///    },
///    "signature": "PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519"
///  },
///  "timestamp": 1571140551543
///}"##;
/// let result = verify_message(valid_message.as_bytes());
/// assert!(result.is_ok());
///```
pub fn verify_message<T: AsRef<[u8]>>(msg: T) -> Result<()> {
    let (key, sig, bytes) = get_pubkey_sig_bytes_from_ssb_message(msg.as_ref())?;
    key.verify(&bytes, &sig)
        .map_err(|_| snafu::NoneError)
        .context(InvalidSignature)
}

/// Verify the signature of a ssb `message.value`.
///
/// It expects the messages to be the JSON encoded message value of shape: `{
/// previous: "",
/// author: "",
/// sequence: ...,
/// timestamp: ...,
/// content: {},
/// signature: ""
/// }`
///
/// Returns `Ok(())` if the signature did sign this message, otherwise `Err(InvalidSignature)`
///
/// # Example
///```
///use ssb_verify_signatures::verify_message_value;
///let valid_message_value = r##"{
///  "previous": "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
///  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///  "sequence": 8,
///  "timestamp": 1470187438539,
///  "hash": "sha256",
///  "content": {
///    "type": "contact",
///    "contact": "@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519",
///    "following": true,
///    "blocking": false
///  },
///  "signature": "PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519"
///}"##;
/// let result = verify_message_value(valid_message_value.as_bytes());
/// assert!(result.is_ok());
///```
pub fn verify_message_value<T: AsRef<[u8]>>(msg: T) -> Result<()> {
    let (key, sig, bytes) = get_pubkey_sig_bytes_from_ssb_message_value(msg.as_ref())?;
    key.verify(&bytes, &sig)
        .map_err(|_| snafu::NoneError)
        .context(InvalidSignature)
}

/// Verify the signature of a ssb `message.value` with the given hmac key (also known as the
/// 'app key', 'SHS key', 'capabilities key' and 'network identifier').
///
/// It expects the messages to be the JSON encoded message value of shape: `{
/// previous: "",
/// author: "",
/// sequence: ...,
/// timestamp: ...,
/// content: {},
/// signature: ""
/// }`
///
/// Returns `Ok(())` if the signature did sign this message, otherwise `Err(InvalidSignature)`
///
/// # Example
/// ```
/// use ssb_verify_signatures::verify_message_value_with_hmac;
/// let valid_message_value_with_unique_hmac = r##"{
///  "previous": null,
///  "sequence": 1,
///  "author": "@EnPSnV1HZdyE7pcKxqukyhmnwE9076RtAlYclaUMX5g=.ed25519",
///  "timestamp": 1624360181359,
///  "hash": "sha256",
///  "content": {
///    "type": "example"
///  },
///  "signature": "w670wqnD1A5blFaYxDiIhPOTwz8I7syVx30jac1feQK/OywHFfrcLVw2S1KmxK9GzWxvKxLMle/jKjf2+pHtAg==.sig.ed25519"
/// }"##;
/// let msg_bytes = valid_message_value_with_unique_hmac.as_bytes();
/// // this represents the unique hmac the message value was originally signed with
/// let hmac = base64::decode("CbwuwYXmZgN7ZSuycCXoKGOTU1dGwBex+paeA2kr37U=").unwrap();
/// let result = verify_message_value_with_hmac(&msg_bytes, &hmac);
/// assert!(result.is_ok());
/// ```
pub fn verify_message_value_with_hmac<T: AsRef<[u8]>>(msg: T, hmac: &[u8]) -> Result<()> {
    let (key, sig, bytes) = get_pubkey_sig_bytes_from_ssb_message_value(msg.as_ref())?;
    // deserialize hmac from given byte slice, returns `None` if the slice length isn't 32
    let hmac_key = NetworkKey::from_slice(hmac).context(InvalidHmac)?;
    // generate hmac auth tag from msg bytes
    let tag = hmac_key.authenticate(&bytes);
    let tag_bytes = tag.as_bytes();
    // verify using key, tag and signature
    key.verify(tag_bytes, &sig)
        .map_err(|_| snafu::NoneError)
        .context(InvalidSignature)
}

pub const CHUNK_SIZE: usize = 50;

/// Checks signatures of a slice of message values in parallel.
///
/// It expects the messages to be the JSON encoded message value of shape: `{
/// previous: "",
/// author: "",
/// sequence: ...,
/// timestamp: ...,
/// content: {},
/// signature: ""
/// }`
///
/// Uses `ed25519_dalek`'s batch verify method to take advantage of processors with SIMD
/// instructions, and process them in parallel using `rayon`.
///
/// You may pass an `Option<usize>` for `chunk_size` or, if `None`, a default of [CHUNK_SIZE] is used.
///
/// Returns `Ok(())` if _all_ messages are ok, and an `Err(InvalidSignature)` if any signature fails.
/// Unfortunately `ed25519_dalek::verify_batch` does not return _which_ message failed to verify,
/// If you need to work out which message failed, you might have to `find` it using the [verify_message_value] method in this crate once this method returns an error.
///
/// # Example
///```
///use ssb_verify_signatures::par_verify_message_values;
///let valid_message_value = r##"{
///  "previous": "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
///  "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///  "sequence": 8,
///  "timestamp": 1470187438539,
///  "hash": "sha256",
///  "content": {
///    "type": "contact",
///    "contact": "@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519",
///    "following": true,
///    "blocking": false
///  },
///  "signature": "PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519"
///}"##.as_bytes();
/// let values = [valid_message_value, valid_message_value, valid_message_value];
/// let result = par_verify_message_values(&values, None);
/// assert!(result.is_ok());
///```
pub fn par_verify_message_values<T: AsRef<[u8]>>(
    msgs: &[T],
    chunk_size: Option<usize>,
) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
{
    par_verify(
        msgs,
        chunk_size,
        get_pubkey_sig_bytes_from_ssb_message_value,
    )
}

/// Checks signatures of a slice of messages in parallel.
///
/// It expects the messages to be the JSON encoded message of shape: `{key: "", value: {...}}`
///
/// Uses `ed25519_dalek`'s batch verify method to take advantage of processors with SIMD
/// instructions, and process them in parallel using `rayon`.
///
/// You may pass an `Option<usize>` for `chunk_size` or, if `None`, a default of `CHUNK_SIZE` is used.
///
/// Returns `Ok(())` if _all_ messages are ok, and an `Err(InvalidSignature)` if any signature fails.
/// Unfortunately `ed25519_dalek::verify_batch` does not return _which_ message failed to verify,
/// If you need to work out which message failed, you might have to `find` it using the [verify_message] method in this crate once this method returns an error.
///
/// # Example
///```
///use ssb_verify_signatures::par_verify_messages;
///let valid_message = r##"{
///  "key": "%kmXb3MXtBJaNugcEL/Q7G40DgcAkMNTj3yhmxKHjfCM=.sha256",
///  "value": {
///    "previous": "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
///    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
///    "sequence": 8,
///    "timestamp": 1470187438539,
///    "hash": "sha256",
///    "content": {
///      "type": "contact",
///      "contact": "@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519",
///      "following": true,
///      "blocking": false
///    },
///    "signature": "PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519"
///  },
///  "timestamp": 1571140551543
///}"##.as_bytes();
/// let messages = [valid_message, valid_message, valid_message];
/// let result = par_verify_messages(&messages, None);
/// assert!(result.is_ok());
///```
pub fn par_verify_messages<T: AsRef<[u8]>>(msgs: &[T], chunk_size: Option<usize>) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
{
    par_verify(msgs, chunk_size, get_pubkey_sig_bytes_from_ssb_message)
}

fn par_verify<T: AsRef<[u8]>, M: Fn(&[u8]) -> Result<KeySigBytes>>(
    msgs: &[T],
    chunk_size: Option<usize>,
    mapper: M,
) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
    M: Sync,
{
    msgs.as_parallel_slice()
        .par_chunks(chunk_size.unwrap_or(CHUNK_SIZE))
        .try_fold(
            || (),
            |_, chunk| {
                let keys_sigs_bytes = chunk
                    .iter()
                    .map(|msg| mapper(msg.as_ref()))
                    .collect::<Result<ArrayVec<[KeySigBytes; CHUNK_SIZE]>>>()?;

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

                dalek_verify_batch(bytes.as_slice(), sigs.as_slice(), keys.as_slice())
                    .map_err(|_| snafu::NoneError)
                    .context(InvalidSignature)
            },
        )
        .try_reduce(|| (), |_, _| Ok(()))
}

fn get_pubkey_sig_bytes_from_ssb_message_value(msg: &[u8]) -> Result<KeySigBytes> {
    let mut verifiable_msg: Value = from_slice(&msg).context(InvalidSsbMessage)?;
    let message_value: SsbMessageValue =
        serde_json::from_slice(msg).context(InvalidSsbMessageJson)?;

    get_pubkey_sig_bytes_from_decoded_values(&mut verifiable_msg, &message_value)
}

fn get_pubkey_sig_bytes_from_ssb_message(msg: &[u8]) -> Result<KeySigBytes> {
    let message_value: Value = from_slice(&msg).context(InvalidSsbMessage)?;
    let message: SsbMessage = serde_json::from_slice(msg).context(InvalidSsbMessageJson)?;

    let mut verifiable_msg = if let Value::Object(kv) = message_value {
        kv.get("value").context(InvalidMessageNoValue)?.clone()
    } else {
        return Err(Error::InvalidMessageNoValue);
    };

    get_pubkey_sig_bytes_from_decoded_values(&mut verifiable_msg, &message.value)
}

fn get_pubkey_sig_bytes_from_decoded_values(
    verifiable_msg: &mut Value,
    message_value: &SsbMessageValue,
) -> Result<KeySigBytes> {
    // Parse the signature string
    let sig_bytes = get_sig_bytes(message_value.signature.as_bytes())?;
    // Parse the author string
    let key_bytes = get_key_bytes(message_value.author.as_bytes())?;

    // Convert the signature bytes to a dalek signature
    let key = PublicKey::from_bytes(&key_bytes)
        .map_err(|_| snafu::NoneError)
        .context(InvalidKeyBytes)?;

    // Convert the author bytes to a dalek pub key
    let sig = Signature::new(sig_bytes);

    // Modify the val by removing the signature
    if let Value::Object(ref mut msg) = verifiable_msg {
        msg.remove("signature".to_owned());
    };

    // Encode the message to a string with out the signature. This was how it was when it was
    // signed by the author.
    let bytes_to_verify =
        to_string(&verifiable_msg, false).context(UnableToEncodeMessageToValidSigningEncoding)?;

    Ok((key, sig, bytes_to_verify.into_bytes()))
}

fn get_sig_bytes(sig: &[u8]) -> Result<[u8; 64]> {
    let caps = SIGNATURE_BYTES_REGEX
        .captures(sig)
        .context(InvalidSignatureString)?;
    let sig_str = caps.get(1).context(InvalidSignatureString)?;
    let mut buff = [0; 64];
    decode_config_slice(sig_str.as_bytes(), base64::STANDARD, &mut buff)
        .context(InvalidSignatureStringBase64Encoding)?;
    Ok(buff)
}

fn get_key_bytes(key: &[u8]) -> Result<[u8; 32]> {
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

    use crate::{
        get_key_bytes, get_sig_bytes, par_verify_message_values, par_verify_messages,
        verify_message, verify_message_value, verify_message_value_with_hmac, Error,
    };
    use base64;
    use ssb_crypto::{AsBytes, NetworkKey};

    #[test]
    fn verify_message_works() {
        let msg = VALID_MESSAGE.as_bytes();
        assert!(verify_message(&msg).is_ok());
    }
    #[test]
    fn verify_message_value_works() {
        let msg = VALID_MESSAGE_VALUE.as_bytes();
        assert!(verify_message_value(&msg).is_ok());
    }

    #[test]
    fn par_verify_messages_works() {
        let msgs = [
            VALID_MESSAGE.as_bytes(),
            VALID_MESSAGE.as_bytes(),
            VALID_MESSAGE.as_bytes(),
        ];
        let result = par_verify_messages(&msgs, None);
        assert!(result.is_ok());
    }
    #[test]
    fn par_verify_messages_values_works() {
        let msgs = [
            VALID_MESSAGE_VALUE.as_bytes(),
            VALID_MESSAGE_VALUE.as_bytes(),
            VALID_MESSAGE_VALUE.as_bytes(),
        ];
        let result = par_verify_message_values(&msgs, None);
        assert!(result.is_ok());
    }
    #[test]
    fn par_verify_batch_works_with_errors() {
        let msgs = [
            VALID_MESSAGE.as_bytes(),
            INVALID_MESSAGE.as_bytes(),
            VALID_MESSAGE.as_bytes(),
        ];
        let result = par_verify_messages(&msgs, None);
        match result {
            Err(Error::InvalidSignature {}) => {}
            _ => panic!(),
        }
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

    #[test]
    fn verify_message_value_with_hmac_works() {
        let msg = VALID_MESSAGE_VALUE_UNIQUE_HMAC.as_bytes();
        let hmac = base64::decode("CbwuwYXmZgN7ZSuycCXoKGOTU1dGwBex+paeA2kr37U=").unwrap();
        let result = verify_message_value_with_hmac(&msg, &hmac);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_message_value_with_incorrect_hmac_fails() {
        let msg = VALID_MESSAGE_VALUE_UNIQUE_HMAC.as_bytes();
        let hmac = NetworkKey::SSB_MAIN_NET;
        let hmac_bytes = hmac.as_bytes();
        let result = verify_message_value_with_hmac(&msg, &hmac_bytes);
        match result {
            Err(Error::InvalidSignature {}) => {}
            _ => panic!(),
        }
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
    const VALID_MESSAGE_VALUE: &str = r##"{
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
    const INVALID_MESSAGE: &str = r##"{
  "key": "%kmXb3MXtBJaNugcEL/Q7G40DgcAkMNTj3yhmxKHjfCM=.sha256",
  "value": {
    "previous": "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
    "author": "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    "sequence": 9,
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

    const VALID_MESSAGE_VALUE_UNIQUE_HMAC: &str = r##"{
  "previous": null,
  "sequence": 1,
  "author": "@EnPSnV1HZdyE7pcKxqukyhmnwE9076RtAlYclaUMX5g=.ed25519",
  "timestamp": 1624360181359,
  "hash": "sha256",
  "content": {
    "type": "example"
  },
  "signature": "w670wqnD1A5blFaYxDiIhPOTwz8I7syVx30jac1feQK/OywHFfrcLVw2S1KmxK9GzWxvKxLMle/jKjf2+pHtAg==.sig.ed25519"
}"##;
}
