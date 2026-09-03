//! A 32-byte key split 2-of-3 between three custodians, printed (redacted),
//! rebuilt from two of them, and checked in constant time.
//!
//! cargo run --example custody

use classified::ClassifiedBytes;
use classified_shamir::{reconstruct_bytes, split_bytes, Threshold};

fn main() {
    let key = ClassifiedBytes::<32>::new([0xA5; 32]).expect("32 bytes");
    let threshold = Threshold::new(2, 3).expect("2 <= 3");

    let shares = split_bytes(&key, threshold).expect("the OS generator works");
    for share in &shares {
        // a log line cannot leak a share
        println!("custodian {} holds {share:?}", share.index());
    }

    // custodians 1 and 3 present their shares
    let rebuilt: ClassifiedBytes<32> = reconstruct_bytes([&shares[0], &shares[2]], threshold).expect("two distinct shares");
    println!("rebuilt matches the original: {}", rebuilt.ct_eq(&key));
    println!("the key itself prints as {key:?}");
}
