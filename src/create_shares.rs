use {
    honest::{
        polynomial::evaluate_polynomial::evaluate_polynomial,
        types::secure_types::SecretBigUint
    },
    num_bigint::{BigUint,ToBigUint},
    rand::rngs::OsRng,
    rand_utils::BigUintGenerator,
    secrecy::{ExposeSecret},
};

// 
// /// Generates shares using Shamir's Secret Sharing.
// /// 
// /// - `secret`: The secret to share, wrapped in `Secret<BigUint>`.
// /// - `threshold`: Minimum number of shares required to reconstruct the secret.
// /// - `total_shares`: Total number of shares to generate.
// /// - `prime`: A large prime number larger than the secret and coefficients.
/// Generates shares using Shamir's Secret Sharing.
pub fn create_shares(
    secret: SecretBigUint,
    threshold: usize,
    total_shares: usize,
    prime: &BigUint,
) -> Vec<(BigUint, BigUint)> {
    assert!(
        threshold <= total_shares,
        "Threshold cannot exceed total shares"
    );

    let mut rng = OsRng;

    // Coefficients of the polynomial: secret is the constant term.
    let mut coefficients = vec![
        secret.expose_secret().0.clone()
    ];

    for _ in 1..threshold {
        coefficients.push(
            rng.gen_biguint_below(prime)
        );
        // coefficients.push(rng.gen_biguint_range(prime));
    }

    // Create the shares.
    let shares = (1..=total_shares)
        .map(|i| {
            let x = i.to_biguint().unwrap();

            let y = evaluate_polynomial(
                &coefficients,
                &x,
                prime
            );
            
            (x, y)
        })
        .collect();

    shares
}

#[cfg(test)]
mod tests {
    use {
        crate::reconstruct_key::{
            reconstruct_key_safe,
            reconstruct_key_secret_safe
        },
        honest::types::secure_types::{
            SecureBigInt,
            SecureBigUint
        }
    };
use crate::{
    reconstruct_secret::reconstruct_secret_fast as rec_sec,
    reconstruct_secret::reconstruct_secret as rec_sec2,
};

    use super::*;
    use num_bigint::{BigInt, BigUint, ToBigInt};
    use num_traits::{One, Zero};
    use secrecy::SecretBox;

    fn get_test_prime() -> BigUint {
        // A safe 256-bit prime (for demo purposes); in practice use a securely generated prime.
        BigUint::parse_bytes(
            b"115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap()
    }

    fn get_secret(value: u64) -> SecretBigUint {
        SecretBox::new(Box::new(SecureBigUint(value.into())))
    }

    fn reconstruct_secret(
        shares: &[(BigUint, BigUint)],
        prime: &BigUint,
    ) -> BigUint {
        let mut secret = BigUint::zero();

        for (i, (xi, yi)) in shares.iter().enumerate() {
            let mut num = BigUint::one();
            let mut denom = BigUint::one();

            for (j, (xj, _)) in shares.iter().enumerate() {
                if i != j {
                    num = (&num * xj) % prime;
                    // let denom_part = (xj - xi + prime) % prime;

                    // let denom_part = if xj > xi {
                    //     (xj - xi) % prime
                    // } else {
                    //     (prime + xj - xi) % prime
                    // };

                    let denom_part = (xj + prime - xi) % prime;

                    denom = (&denom * denom_part) % prime;
                }
            }

            let inv_denom = modinverse(&denom, prime).expect("No inverse exists");
            let lagrange_coeff = (&num * &inv_denom) % prime;

            secret = (secret + (yi * &lagrange_coeff)) % prime;
        }

        secret
    }

    fn modinverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
        let (mut mn, mut xy) = ( (m.clone(), a.clone()), (BigInt::zero(), BigInt::one()) );

        while mn.1 != BigUint::zero() {
            let quotient = &mn.0 / &mn.1;
            mn = (mn.1.clone(), &mn.0 - &quotient * &mn.1);
            xy = (xy.1.clone(), &xy.0 - &quotient.to_bigint().unwrap() * &xy.1);
        }

        if mn.0 != BigUint::one() { return None; }

        Some((xy.0 % m.to_bigint().unwrap() + m.to_bigint().unwrap()) % m.to_bigint().unwrap())
            .map(|v| v.to_biguint().unwrap())
    }

    #[test]
    fn test_share_count() {
        let prime = get_test_prime();
        let secret = get_secret(42);
        let shares = create_shares(secret, 3, 5, &prime);
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_share_uniqueness() {
        let prime = get_test_prime();
        let secret = get_secret(99);
        let shares = create_shares(secret, 3, 5, &prime);
        let unique: std::collections::HashSet<_> = shares.iter().collect();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn test_secret_reconstruction() {
        let prime = get_test_prime();
        let original_secret = BigUint::from(123u64);
        let secret = SecretBox::new(Box::new(SecureBigUint(original_secret.clone())));

        let shares = create_shares(secret, 3, 5, &prime);

        let selected_shares = &shares[..3];
        let reconstructed = reconstruct_secret(selected_shares, &prime);
        assert_eq!(reconstructed, original_secret);
    }

    #[test]
    fn test_secret_reconstruction_internal() {
        let prime = get_test_prime();
        let original_secret = BigUint::from(123u64);
        let secret = SecretBox::new(Box::new(SecureBigUint(original_secret.clone())));

        let shares = create_shares(secret, 3, 5, &prime);

        let selected_shares = &shares[..3];
        let reconstructed = rec_sec(selected_shares, &prime);
        assert_eq!(reconstructed, original_secret);
    }

    #[test]
    #[should_panic]
    fn test_invalid_threshold() {
        let prime = get_test_prime();
        let secret = get_secret(55);
        // threshold higher than total_shares
        let _ = create_shares(secret, 6, 5, &prime);
    }

    #[test]
    fn test_key_reconstruction_with_subtle() {
        let data1 = vec![1u8, 2, 3, 4];
        let data2 = vec![1u8, 2, 0, 4];

        let mut combined = vec![];
        combined.extend_from_slice(&data1);
        combined.extend_from_slice(&data2);

        let reconstructed = reconstruct_key_safe(&combined);

        // Only bytes that matched will survive (others become 0)
        assert_eq!(reconstructed, vec![1, 2, 0, 4]);
    }

    #[test]
    fn test_key_secret_safe_zeroize() {
        let mut combined = vec![42u8; 64];
        let secret = reconstruct_key_secret_safe(&combined);

        // We can't directly access the internal value without exposing it
        let unboxed = secret.expose_secret();
        assert_eq!(unboxed.len(), 32); // Half the input length

        // Security idea: run a `zeroize` manually and check contents were wiped if mutable
        // (though secrecy's drop-based zeroization handles this)
    }

}
