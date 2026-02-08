use std::time::{SystemTime, UNIX_EPOCH};

use honest::types::secure_types::{
    SecureBigUint,
    SecretBigUint
};
use num_bigint::BigUint;
use secrecy::{SecretBox};

use crate::create_shares::create_shares;

/// Function to generate Shamir's Secret Shares with optional time decay
pub fn generate_shares(
    secret: &str,
    num_shares: usize,
    threshold: usize,
    expire_seconds: u64,
    prime: &BigUint
) -> Vec<(BigUint, BigUint)> {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let expiring_secret = format!(
        "{}|{}",
        secret,
        current_time + expire_seconds
    );

    let secret_bytes = expiring_secret.as_bytes();

    // Interpret the byte array as a number
    let secret_biguint = BigUint::from_bytes_be(secret_bytes);

    // Secure it
    let wrapped: SecretBigUint = SecretBox::new(
        Box::new(
            SecureBigUint(secret_biguint)
        )
    );

    // Split into shares
    create_shares(
        wrapped,
        threshold,
        num_shares,
        prime
    )
}



// use secrecy::{
//     ExposeSecret,
//     SecretString
// };
// use std::fs;
// use std::time::{
//     SystemTime,
//     UNIX_EPOCH
// };
// use zeroize::Zeroize;
// 
// use crate::create_shares::create_shares;
// 
// 
// /// Function to generate Shamir's Secret Shares with optional time decay
// fn generate_shares(
//     secret: &str,
//     num_shares: usize,
//     threshold: usize,
//     expire_seconds: u64
// ) -> Vec<(usize, Vec<u8>)> {
//     let current_time = SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .unwrap()
//         .as_secs();
// 
//     let expiring_secret = format!(
//         "{}|{}",
//         secret,
//         current_time + expire_seconds
//     );
//     
//     let secret_bytes = expiring_secret.as_bytes();
//     
//     // Split the secret into shares
//     let shares = create_shares(
//         secret_bytes,
//         threshold,
//         num_shares,
//     ).expect("Failed to split secret");
//     
//     shares
// }
// 