use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssb_verify_signatures::{par_verify, par_verify_batch, verify};

pub fn verify_bench(c: &mut Criterion) {
    c.bench_function("verify", |b| {
        b.iter(|| verify(black_box(VALID_MESSAGE.as_bytes())))
    });
}

pub fn par_verify_batch_bench(c: &mut Criterion) {
    let msgs = [VALID_MESSAGE.as_bytes(); 1000];
    c.bench_function("par_verify_batch", |b| {
        b.iter(|| par_verify_batch(black_box(&msgs)))
    });
    c.bench_function("par_verify", |b| b.iter(|| par_verify(black_box(&msgs))));
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

criterion_group! {
    name = verify_batch;
    config = Criterion::default().sample_size(10);
    targets = par_verify_batch_bench
}
criterion_group!(verify_single, verify_bench);

criterion_main!(verify_batch, verify_single);
