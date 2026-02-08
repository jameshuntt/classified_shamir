use subtle::{ConstantTimeEq, ConditionallySelectable};
use secrecy::{SecretBox};
use zeroize::Zeroize;

pub(crate) fn reconstruct_key(received_data: &[u8]) -> Vec<u8> {
    // Extract key shards from received data (simple example)
    let shard_size = received_data.len() / 2;
    let shard1 = received_data[..shard_size].to_vec();
    let shard2 = received_data[shard_size..].to_vec();

    // Reconstruct the key
    let reconstructed_key: Vec<u8> = shard1
        .iter()
        .zip(&shard2)
        .map(|(a, b)| a ^ b)
        .collect();

    reconstructed_key
}

pub(crate) fn reconstruct_key_safe(received_data: &[u8]) -> Vec<u8> {
    // Extract key shards from received data using a more advanced approach
    let shard_size = received_data.len() / 2;
    let shard1 = received_data[..shard_size].to_vec();
    let shard2 = received_data[shard_size..].to_vec();

    // Reconstruct the key using ECC and constant-time comparison
    let reconstructed_key: Vec<u8> = shard1
        .iter()
        .zip(&shard2)
        .map(|(a, b)| u8::conditional_select(&0u8, a, a.ct_eq(b)))
        // .map(|(a, b)| if a == b { *a } else { 0 })
        // .map(|(a, b)| a.ct_eq(b).select(a.clone(), 0))
        
        // original     .map(|(a, b)| u8::conditional_select(a, &0u8, a.ct_eq(b)))

        .collect();

    reconstructed_key
}

pub(crate) fn reconstruct_key_dynamic(received_data: &[u8]) -> Vec<u8> {
    assert!(received_data.len() % 2 == 0, "Input must be even-length");
    let shard_size = received_data.len() / 2;
    let (shard1, shard2) = received_data.split_at(shard_size);

    shard1.iter()
        .zip(shard2)
        .map(|(a, b)| a ^ b)
        .collect()
}

pub(crate) fn reconstruct_key_dynamic_safe(received_data: &[u8]) -> Vec<u8> {
    assert!(received_data.len() % 2 == 0, "Input must be even-length");
    let shard_size = received_data.len() / 2;
    let (shard1, shard2) = received_data.split_at(shard_size);

    shard1.iter()
        .zip(shard2)
        .map(|(a, b)| u8::conditional_select(a, &0u8, a.ct_eq(b)))
        .collect()
}



#[inline(always)]
pub(crate) fn reconstruct_key_secret(received_data: &[u8]) -> SecretBox<Vec<u8>> {
    assert!(received_data.len() % 2 == 0, "Input must be even-length");
    let shard_size = received_data.len() / 2;
    let (shard1, shard2) = received_data.split_at(shard_size);

    let mut reconstructed: Vec<u8> = shard1.iter()
        .zip(shard2)
        .map(|(a, b)| a ^ b)
        .collect();

    let boxed = SecretBox::new(Box::new(reconstructed.clone()));

    reconstructed.zeroize(); // Clear original
    boxed
}

#[inline(always)]
pub(crate) fn reconstruct_key_secret_safe(received_data: &[u8]) -> SecretBox<Vec<u8>> {
    assert!(received_data.len() % 2 == 0, "Input must be even-length");
    let shard_size = received_data.len() / 2;
    let (shard1, shard2) = received_data.split_at(shard_size);

    let mut reconstructed: Vec<u8> = shard1.iter()
        .zip(shard2)
        .map(|(a, b)| u8::conditional_select(a, &0u8, a.ct_eq(b)))
        .collect();

    let boxed = SecretBox::new(Box::new(reconstructed.clone()));

    reconstructed.zeroize();
    boxed
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
use std::arch::x86_64::*;

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
pub fn reconstruct_key_simd(received_data: &[u8]) -> Option<SecretBox<Vec<u8>>> {
    if received_data.len() != 32 {
        return None;
    }
    unsafe {
        let (a, b) = received_data.split_at(16);
        let reg1 = _mm_loadu_si128(a.as_ptr() as *const __m128i);
        let reg2 = _mm_loadu_si128(b.as_ptr() as *const __m128i);
        let out = _mm_xor_si128(reg1, reg2);
        let mut buffer = [0u8; 16];
        _mm_storeu_si128(buffer.as_mut_ptr() as *mut __m128i, out);
        Some(SecretBox::new(buffer.to_vec()))
    }
}


// 
// fn reconstruct_key(shares: Vec<(BigUint, BigUint)>) -> BigUint {
//     let prime = BigUint::from(208351617316091241234326746312124448251235562226470491514186331217050270460481u128);
//     reconstruct_secret(&shares, &prime)
// }
// 
