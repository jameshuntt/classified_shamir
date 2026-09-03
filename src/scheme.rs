use classified::{ClassifiedBuffer, ClassifiedBytes};
use honest_shamir::rand_core::TryCryptoRng;
use honest_shamir::{Share, Threshold};

use crate::{ClassifiedShare, Error};

/// Split a buffer into `threshold.total()` shares using `rng`.
///
/// The secret is exposed to the arithmetic for the duration of the call;
/// the plain shares it produces are moved into containers one by one, so
/// no copy of any share outlives the return.
pub fn split_with<R: TryCryptoRng + ?Sized>(
    secret: &ClassifiedBuffer,
    threshold: Threshold,
    rng: &mut R,
) -> Result<Vec<ClassifiedShare>, Error> {
    let plain = secret.expose(|view| honest_shamir::split_with(view.as_bytes(), threshold, rng))?;
    wrap_all(plain)
}

/// [`split_with`] for a fixed-size secret.
pub fn split_bytes_with<const N: usize, R: TryCryptoRng + ?Sized>(
    secret: &ClassifiedBytes<N>,
    threshold: Threshold,
    rng: &mut R,
) -> Result<Vec<ClassifiedShare>, Error> {
    let plain = secret.expose(|view| honest_shamir::split_with(view.as_bytes(), threshold, rng))?;
    wrap_all(plain)
}

/// [`split_with`] using the operating system's generator.
#[cfg(feature = "os-rng")]
pub fn split(secret: &ClassifiedBuffer, threshold: Threshold) -> Result<Vec<ClassifiedShare>, Error> {
    split_with(secret, threshold, &mut honest_shamir::rand_core::OsRng)
}

/// [`split_bytes_with`] using the operating system's generator.
#[cfg(feature = "os-rng")]
pub fn split_bytes<const N: usize>(secret: &ClassifiedBytes<N>, threshold: Threshold) -> Result<Vec<ClassifiedShare>, Error> {
    split_bytes_with(secret, threshold, &mut honest_shamir::rand_core::OsRng)
}

/// Rebuild the secret from the first `threshold.required()` shares, into a
/// buffer bounded to the secret's length.
///
/// Shares are taken by reference, so a subset is a list of borrows:
/// `reconstruct([&shares[0], &shares[3]], threshold)`.
pub fn reconstruct<'a>(
    shares: impl IntoIterator<Item = &'a ClassifiedShare>,
    threshold: Threshold,
) -> Result<ClassifiedBuffer, Error> {
    let plain: Vec<Share> = shares
        .into_iter()
        .map(|share| share.expose(|view| Share::new(share.index(), view.as_bytes().to_vec())))
        .collect::<Result<_, _>>()?;
    let secret = honest_shamir::reconstruct(&plain, threshold)?;
    let len = secret.len();
    Ok(ClassifiedBuffer::try_from_vec(secret, len)?)
}

/// [`reconstruct`] into a fixed-size container. Refused with
/// [`ClassifiedError::LengthMismatch`](classified::ClassifiedError::LengthMismatch)
/// when the rebuilt secret is not `N` bytes.
pub fn reconstruct_bytes<'a, const N: usize>(
    shares: impl IntoIterator<Item = &'a ClassifiedShare>,
    threshold: Threshold,
) -> Result<ClassifiedBytes<N>, Error> {
    let buffer = reconstruct(shares, threshold)?;
    Ok(buffer.expose(|view| ClassifiedBytes::try_from_slice(view.as_bytes()))?)
}

/// Re-randomize `shares` in place: the same secret, new shares that no
/// longer combine with the ones they replace. All shares that must keep
/// working are refreshed together.
pub fn refresh_with<R: TryCryptoRng + ?Sized>(
    shares: &mut [ClassifiedShare],
    threshold: Threshold,
    rng: &mut R,
) -> Result<(), Error> {
    let mut plain: Vec<Share> = shares
        .iter()
        .map(|share| share.expose(|view| Share::new(share.index(), view.as_bytes().to_vec())))
        .collect::<Result<_, _>>()?;
    honest_shamir::refresh_with(&mut plain, threshold, rng)?;
    for (slot, fresh) in shares.iter_mut().zip(plain) {
        *slot = wrap(fresh)?;
    }
    Ok(())
}

/// [`refresh_with`] using the operating system's generator.
#[cfg(feature = "os-rng")]
pub fn refresh(shares: &mut [ClassifiedShare], threshold: Threshold) -> Result<(), Error> {
    refresh_with(shares, threshold, &mut honest_shamir::rand_core::OsRng)
}

fn wrap(share: Share) -> Result<ClassifiedShare, Error> {
    let index = share.index();
    let bytes = share.into_bytes();
    let len = bytes.len();
    ClassifiedShare::new(index, ClassifiedBuffer::try_from_vec(bytes, len)?)
}

fn wrap_all(shares: Vec<Share>) -> Result<Vec<ClassifiedShare>, Error> {
    shares.into_iter().map(wrap).collect()
}
