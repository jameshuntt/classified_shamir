# classified_shamir

Shamir secret sharing in [`classified`](https://crates.io/crates/classified)
containers.

[`honest_shamir`](https://crates.io/crates/honest_shamir) does the
arithmetic on plain bytes. This crate keeps the bytes in containers on both
sides of it: the secret goes in as a `ClassifiedBuffer` or
`ClassifiedBytes<N>`, each share comes out as a `ClassifiedShare`, and
reconstruction hands back a container. Nothing is a bare `Vec<u8>` in your
hands, `Debug` prints `[REDACTED]` at every step, equality is constant
time, and every intermediate copy is zeroized when the call returns.

```rust
use classified::ClassifiedBytes;
use classified_shamir::{split_bytes, reconstruct_bytes, refresh, Threshold};

// a key that must survive the loss of any one custodian
let key = ClassifiedBytes::<32>::new([0x42; 32]).unwrap();
let threshold = Threshold::new(2, 3).unwrap();
let mut shares = split_bytes(&key, threshold).unwrap();

// shares are containers too
assert_eq!(format!("{:?}", shares[0]), r#"ClassifiedShare { index: 1, len: 32, value: "[REDACTED]" }"#);

// any two rebuild the key, as the same fixed-size type
let rebuilt: ClassifiedBytes<32> = reconstruct_bytes([&shares[2], &shares[0]], threshold).unwrap();
assert!(rebuilt.ct_eq(&key));

// new shares for the same key; the old ones no longer combine with them
refresh(&mut shares, threshold).unwrap();
assert!(reconstruct_bytes::<32>([&shares[1], &shares[2]], threshold).unwrap().ct_eq(&key));
```

A share that arrives from elsewhere becomes a `ClassifiedShare` with
`ClassifiedShare::from_slice(index, bytes)`; one that leaves is read with
`expose`, like every classified container:

```rust
use classified::ClassifiedBuffer;
use classified_shamir::{split, reconstruct, ClassifiedShare, Threshold};

let secret = ClassifiedBuffer::try_from_slice(b"passphrase", 32).unwrap();
let threshold = Threshold::new(2, 3).unwrap();
let shares = split(&secret, threshold).unwrap();

let on_the_wire: (u8, Vec<u8>) = (shares[1].index(), shares[1].expose(|v| v.as_bytes().to_vec()));
let received = ClassifiedShare::from_slice(on_the_wire.0, &on_the_wire.1).unwrap();
assert!(reconstruct([&shares[0], &received], threshold).unwrap().ct_eq(&secret));
```

`split`, `split_bytes` and `refresh` use the operating system's generator
(feature `os-rng`, on by default); the `_with` variants take any
`rand_core::TryCryptoRng`.

## What is and is not here

The policy and the checks are `honest_shamir`'s: `2 <= k <= n`, distinct
non-zero indexes, equal lengths, and **no share authentication**. A wrong
or tampered share rebuilds a wrong secret without complaint; keep a digest
beside the shares, or let the AEAD tag on whatever the secret unlocks be
the check.

`Error` is one of `Error::Shamir(ShamirError)` from the arithmetic or
`Error::Classified(ClassifiedError)` from a container, for example a
rebuilt secret that does not fit the `ClassifiedBytes<N>` asked for.

## License

MIT OR Apache-2.0.
