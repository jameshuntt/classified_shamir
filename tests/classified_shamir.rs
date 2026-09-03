//! Containers in, containers out: the arithmetic is honest_shamir's, so these
//! tests are about what the wrapping adds and preserves.

use classified::{expose, ClassifiedBuffer, ClassifiedBytes, ClassifiedError, Expose};
use classified_shamir::rand_core::SeedableRng;
use classified_shamir::{
    reconstruct, reconstruct_bytes, refresh_with, split_bytes_with, split_with, ClassifiedShare, Error, ShamirError,
    Threshold,
};
use rand_chacha::ChaCha20Rng;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn t(k: u8, n: u8) -> Threshold {
    Threshold::new(k, n).unwrap()
}

#[test]
fn a_buffer_splits_and_every_three_of_five_rebuild_it() {
    let secret = ClassifiedBuffer::try_from_slice(b"the key to the archive", 64).unwrap();
    let shares = split_with(&secret, t(3, 5), &mut rng(1)).unwrap();
    assert_eq!(shares.len(), 5);
    assert_eq!(shares.iter().map(ClassifiedShare::index).collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
    assert!(shares.iter().all(|s| s.len() == 22 && !s.is_empty()));

    for a in 0..5 {
        for b in (a + 1)..5 {
            for c in (b + 1)..5 {
                let rebuilt = reconstruct([&shares[c], &shares[a], &shares[b]], t(3, 5)).unwrap();
                assert!(rebuilt.ct_eq(&secret), "shares {a} {b} {c}");
                assert_eq!(rebuilt.capacity_limit(), 22, "the rebuilt buffer is bounded to its length");
            }
        }
    }
}

#[test]
fn a_fixed_size_key_comes_back_as_the_same_type() {
    let key = ClassifiedBytes::<32>::new([0x42; 32]).unwrap();
    let shares = split_bytes_with(&key, t(2, 3), &mut rng(2)).unwrap();
    let rebuilt: ClassifiedBytes<32> = reconstruct_bytes([&shares[1], &shares[2]], t(2, 3)).unwrap();
    assert_eq!(rebuilt, key);

    let wrong_size = reconstruct_bytes::<16>([&shares[0], &shares[1]], t(2, 3)).unwrap_err();
    assert_eq!(wrong_size, Error::Classified(ClassifiedError::LengthMismatch { expected: 16, actual: 32 }));
}

#[test]
fn shares_are_redacted_and_compare_in_constant_time() {
    let secret = ClassifiedBuffer::try_from_slice(b"hello", 8).unwrap();
    let shares = split_with(&secret, t(2, 2), &mut rng(3)).unwrap();
    assert_eq!(format!("{:?}", shares[0]), r#"ClassifiedShare { index: 1, len: 5, value: "[REDACTED]" }"#);

    let same = shares[0].expose(|v| ClassifiedShare::from_slice(1, v.as_bytes())).unwrap();
    assert_eq!(same, shares[0]);
    assert!(same.ct_eq(&shares[0]));
    assert_ne!(shares[0], shares[1]);
    let other_index = shares[0].expose(|v| ClassifiedShare::from_slice(7, v.as_bytes())).unwrap();
    assert_ne!(other_index, shares[0], "the index is part of equality");
}

#[test]
fn the_expose_trait_and_macro_reach_a_share() {
    let secret = ClassifiedBuffer::try_from_slice(b"ab", 8).unwrap();
    let shares = split_with(&secret, t(2, 2), &mut rng(4)).unwrap();
    let total = expose!(shares[0] => a, shares[1] => b; a.len() + b.len());
    assert_eq!(total, 4);
    assert_eq!(Expose::expose(&shares[0], |v| v.len()), 2);
    let buffer = shares.into_iter().next().unwrap().into_buffer();
    assert_eq!(buffer.len(), 2);
}

#[test]
fn errors_come_through_from_both_layers() {
    let secret = ClassifiedBuffer::try_from_slice(b"x", 8).unwrap();
    let shares = split_with(&secret, t(3, 4), &mut rng(5)).unwrap();
    let few = reconstruct([&shares[0], &shares[1]], t(3, 4)).unwrap_err();
    assert_eq!(few, Error::Shamir(ShamirError::TooFewShares { required: 3, provided: 2 }));
    assert_eq!(few.to_string(), "too few shares: 2 provided, 3 required");
    assert!(std::error::Error::source(&few).is_some());

    let dup = reconstruct([&shares[0], &shares[0], &shares[1]], t(3, 4)).unwrap_err();
    assert_eq!(dup, Error::Shamir(ShamirError::DuplicateIndex(1)));

    assert_eq!(ClassifiedShare::from_slice(0, b"x").unwrap_err(), Error::Shamir(ShamirError::ZeroIndex));
    assert_eq!(ClassifiedShare::from_slice(1, b"").unwrap_err(), Error::Classified(ClassifiedError::EmptyValue));
    let buffer = ClassifiedBuffer::try_from_slice(b"x", 1).unwrap();
    assert_eq!(ClassifiedShare::new(0, buffer).unwrap_err(), Error::Shamir(ShamirError::ZeroIndex));
}

#[test]
fn refreshed_shares_rebuild_the_secret_and_drop_the_old_ones() {
    let secret = ClassifiedBuffer::try_from_slice(b"rotate", 16).unwrap();
    let old = split_with(&secret, t(2, 3), &mut rng(6)).unwrap();
    let mut new = split_with(&secret, t(2, 3), &mut rng(6)).unwrap();
    assert_eq!(old, new, "same seed, same shares, before the refresh");

    refresh_with(&mut new, t(2, 3), &mut rng(7)).unwrap();
    assert!(new.iter().zip(&old).all(|(a, b)| a != b && a.index() == b.index()));
    assert!(reconstruct([&new[0], &new[2]], t(2, 3)).unwrap().ct_eq(&secret));
    assert!(!reconstruct([&old[0], &new[1]], t(2, 3)).unwrap().ct_eq(&secret));
}

#[test]
fn a_share_received_as_bytes_reconstructs_with_a_local_one() {
    let secret = ClassifiedBuffer::try_from_slice(b"transit", 16).unwrap();
    let shares = split_with(&secret, t(2, 3), &mut rng(8)).unwrap();
    // the second holder sends index + bytes over the wire
    let wire: (u8, Vec<u8>) = (shares[1].index(), shares[1].expose(|v| v.as_bytes().to_vec()));
    let received = ClassifiedShare::from_slice(wire.0, &wire.1).unwrap();
    assert!(reconstruct([&shares[0], &received], t(2, 3)).unwrap().ct_eq(&secret));
}

#[cfg(feature = "os-rng")]
#[test]
fn the_os_generator_round_trips() {
    use classified_shamir::{refresh, split, split_bytes};
    let secret = ClassifiedBuffer::try_from_slice(b"from the operating system", 32).unwrap();
    let mut shares = split(&secret, t(2, 4)).unwrap();
    assert!(reconstruct([&shares[3], &shares[1]], t(2, 4)).unwrap().ct_eq(&secret));
    refresh(&mut shares, t(2, 4)).unwrap();
    assert!(reconstruct([&shares[0], &shares[2]], t(2, 4)).unwrap().ct_eq(&secret));

    let key = ClassifiedBytes::<16>::new([9; 16]).unwrap();
    let shares = split_bytes(&key, t(3, 3)).unwrap();
    assert_eq!(reconstruct_bytes::<16>(&shares, t(3, 3)).unwrap(), key);
}
