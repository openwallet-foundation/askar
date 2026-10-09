use elliptic_curve::{bigint::Limb, Curve, SecretKey};

pub fn write_sk<C: Curve>(sk: &SecretKey<C>, out: &mut [u8]) {
    let limbs = sk.as_scalar_value().as_limbs();
    debug_assert_eq!(out.len(), Limb::BYTES * limbs.len());

    for (src, dst) in limbs
        .iter()
        .rev()
        .cloned()
        .zip(out.chunks_exact_mut(Limb::BYTES))
    {
        dst.copy_from_slice(&src.to_be_bytes());
    }
}
