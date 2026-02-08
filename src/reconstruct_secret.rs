use num_bigint::BigUint;
use num_traits::{One, Zero};
use secrecy::SecretBox;

use honest::{
    polynomial::modinv::modinv,
    types::secure_types::{SecretBigUint, SecureBigUint}
};

/// Lagrange reconstruction with modular inverse
pub fn reconstruct_secret(
    shares: &[(BigUint, BigUint)],
    prime: &BigUint
) -> SecretBigUint {
    let mut secret = BigUint::zero();

    for (i, (x_i, y_i)) in shares.iter().enumerate() {
        let mut numerator = BigUint::one();
        let mut denominator = BigUint::one();

        for (j, (x_j, _)) in shares.iter().enumerate() {
            if i != j {
                numerator = (&numerator * x_j) % prime;
                denominator = (&denominator * (x_j - x_i)) % prime;
            }
        }

        let denom_inv = modinv(&denominator, prime)
            .expect("No modular inverse found");

        let lagrange_coeff = (&numerator * denom_inv) % prime;
        secret = (secret + (y_i * &lagrange_coeff)) % prime;
    }

    SecretBox::new(
        Box::new(
            SecureBigUint(secret)
        )
    )
}

/// Reconstruct with `modpow` inverse instead of EEA
pub fn reconstruct_secret_fast_broken(
    shares: &[(BigUint, BigUint)],
    prime: &BigUint
) -> BigUint {
    let mut secret = BigUint::zero();

    for (i, (x_i, y_i)) in shares.iter().enumerate() {
        let mut num = BigUint::one();
        let mut denom = BigUint::one();

        for (j, (x_j, _)) in shares.iter().enumerate() {
            if i != j {
                num = (&num * x_j) % prime;
                denom = (&denom * (x_j - x_i)) % prime;
            }
        }

        let denom_inv = denom.modpow(&(prime - 2u32), prime); // Fermat inverse
        let coeff = (&num * denom_inv) % prime;
        secret = (secret + (y_i * &coeff)) % prime;
    }

    secret
}

pub fn reconstruct_secret_fast(
    shares: &[(BigUint, BigUint)],
    prime: &BigUint
) -> BigUint {
    let mut secret = BigUint::zero();

    for (i, (x_i, y_i)) in shares.iter().enumerate() {
        let mut num = BigUint::one();
        let mut denom = BigUint::one();

        for (j, (x_j, _)) in shares.iter().enumerate() {
            if i != j {
                num = (&num * x_j) % prime;

                // Safe modular subtraction: (x_j - x_i) mod prime
                let diff = (x_j + prime - x_i) % prime;
                denom = (&denom * diff) % prime;
            }
        }

        let denom_inv = denom.modpow(&(prime - 2u32), prime); // Fermat inverse
        let coeff = (&num * denom_inv) % prime;
        secret = (secret + (y_i * &coeff)) % prime;
    }

    secret
}


// 
// /// Reconstructs the secret from a set of shares using Lagrange interpolation.
// /// 
// /// - `shares`: A slice of `(x, y)` tuples representing the shares.
// /// - `prime`: The prime number used during share generation.
// pub fn reconstruct_secret(shares: &[(BigUint, BigUint)], prime: &BigUint) -> SecretBox<BigUint> {
//     let mut secret = BigUint::zero();
// 
//     for i in 0..shares.len() {
//         let (ref x_i, ref y_i) = shares[i];
//         let mut numerator = BigUint::one();
//         let mut denominator = BigUint::one();
// 
//         for j in 0..shares.len() {
//             if i != j {
//                 let (ref x_j, _) = shares[j];
//                 numerator = (numerator * x_j) % prime;
//                 denominator = (denominator * (&x_j - x_i)) % prime;
//             }
//         }
// 
//         // Compute modular inverse of the denominator.
//         let denom_inv = modinv(&denominator, prime).expect("No modular inverse found");
//         let lagrange_coeff = (numerator * denom_inv) % prime;
//         secret = (secret + (y_i * lagrange_coeff)) % prime;
//     }
// 
//     SecretBox::new(secret)
// }
// 
// 
// 
// // Reconstruction using Lagrange interpolation
// pub fn reconstruct_secret_2(shares: &Vec<(BigUint, BigUint)>, prime: &BigUint) -> BigUint {
//     let mut secret = BigUint::zero();
//     
//     for i in 0..shares.len() {
//         let (x_i, y_i) = &shares[i];
//         let mut numerator = BigUint::one();
//         let mut denominator = BigUint::one();
//         
//         for j in 0..shares.len() {
//             if i != j {
//                 let (x_j, _) = &shares[j];
//                 numerator = (numerator * x_j) % prime;
//                 denominator = (denominator * (x_j - x_i)) % prime;
//             }
//         }
//         
//         let lagrange_coeff = (numerator * denominator.modpow(&(prime - 2u32), prime)) % prime;
//         secret = (secret + (y_i * lagrange_coeff)) % prime;
//     }
//     
//     secret
// }
// 
// 