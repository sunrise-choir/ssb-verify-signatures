use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssb_verify_signatures::{
    par_verify_message_values, par_verify_messages, verify_message, verify_message_value,
};

pub fn verify_message_value_bench(c: &mut Criterion) {
    c.bench_function("verify_value", |b| {
        b.iter(|| verify_message_value(black_box(VALID_MESSAGE_VALUE.as_bytes()), None))
    });
}

pub fn par_verify_message_values_bench(c: &mut Criterion) {
    let msgs = vec![VALID_MESSAGE_VALUE.as_bytes().to_owned(); 1000];
    c.bench_function("par_verify_value_batch", |b| {
        b.iter(|| par_verify_message_values(black_box(&msgs), None, None))
    });
}

pub fn verify_message_value_with_hmac_bench(c: &mut Criterion) {
    let hmac = base64::decode("CbwuwYXmZgN7ZSuycCXoKGOTU1dGwBex+paeA2kr37U=").unwrap();
    c.bench_function("verify_value_with_hmac", |b| {
        b.iter(|| {
            verify_message_value(
                black_box(VALID_MESSAGE_VALUE_UNIQUE_HMAC.as_bytes()),
                Some(&hmac),
            )
        })
    });
}

pub fn par_verify_message_values_with_hmac_bench(c: &mut Criterion) {
    let hmac = base64::decode("CbwuwYXmZgN7ZSuycCXoKGOTU1dGwBex+paeA2kr37U=").unwrap();
    let msgs = vec![VALID_MESSAGE_VALUE_UNIQUE_HMAC.as_bytes().to_owned(); 1000];
    c.bench_function("par_verify_value_batch_with_hmac", |b| {
        b.iter(|| par_verify_message_values(black_box(&msgs), Some(&hmac), None))
    });
}

pub fn verify_bench(c: &mut Criterion) {
    c.bench_function("verify", |b| {
        b.iter(|| verify_message(black_box(VALID_MESSAGE.as_bytes())))
    });
}

pub fn par_verify_messages_bench(c: &mut Criterion) {
    let msgs = vec![VALID_MESSAGE.as_bytes().to_owned(); 1000];
    c.bench_function("par_verify_batch", |b| {
        b.iter(|| par_verify_messages(black_box(&msgs), None))
    });
}

// Define the benchmark groups
// `criterion_group!(name_of_group, function_to_benchmark);`
criterion_group!(verify_batch, par_verify_messages_bench);
criterion_group!(verify_single, verify_bench);
criterion_group!(verify_batch_value, par_verify_message_values_bench);
criterion_group!(verify_single_value, verify_message_value_bench);
criterion_group!(
    verify_batch_value_with_hmac,
    par_verify_message_values_with_hmac_bench
);
criterion_group!(
    verify_single_value_with_hmac,
    verify_message_value_with_hmac_bench
);

// Generate a `main` function and execute the benchmark groups
criterion_main!(
    verify_batch,
    verify_single,
    verify_batch_value,
    verify_single_value,
    verify_batch_value_with_hmac,
    verify_single_value_with_hmac
);

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
