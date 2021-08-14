# ssb-verify-signatures

[![Build Status](https://travis-ci.org/sunrise-choir/ssb-verify-signatures.svg?branch=master)](https://travis-ci.org/sunrise-choir/ssb-verify-signatures) [![Documentation badge](https://img.shields.io/badge/rust-docs-blue)](https://sunrise-choir.github.io/ssb-verify-signatures/ssb_verify_signatures/index.html)

Verify Secure Scuttlebutt message signatures (in parallel).

## How is this different to [ssb-legacy-msg](https://github.com/sunrise-choir/ssb-legacy-msg)?

It's built on top of `ssb-legacy-msg` and `ssb-legacy-msg-data` but exposes a hopefully easier
api, and most importantly it lets you _batch process_ a collection of messages. 

Batch processing is good for two reasons:
- it means we can utilise multiple cores using [rayon](https://docs.rs/rayon/1.2.0/rayon/index.html)
- it means we can use the [ed25519_dalek verify_batch](https://docs.rs/ed25519-dalek/0.9.1/ed25519_dalek/fn.verify_batch.html) function that takes advantage of
processor SIMD instructions. 

## Benchmarks

Benchmarking on a 2016 2 core i5 shows that batch processing with `par_verify_messages` is ~3.6 times faster than using `verify_message` 

Benchmarking on Android on a [One Plus 5T](https://en.wikipedia.org/wiki/OnePlus_5T) (8 core arm64) shows that batch processing with `par_verify_messages` is ~9.9 times faster than using `verify_message`!

Benchmarks can be run with `cargo criterion`.

## License

LGPL-3.0
