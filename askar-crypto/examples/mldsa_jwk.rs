use askar_crypto::{
    alg::{AnyKey, AnyKeyCreate, KeyAlg},
    jwk::{FromJwk, ToJwk},
    sign::{KeySigVerify, KeySign},
};

fn main() {
    run().expect("ML-DSA JWK example failed");
}

fn run() -> Result<(), askar_crypto::Error> {
    let message = b"post-quantum verifiable credential payload";

    for alg in [KeyAlg::MlDsa44, KeyAlg::MlDsa65, KeyAlg::MlDsa87] {
        let key = Box::<AnyKey>::random_det(alg, b"askar ML-DSA JWK example")?;
        let signature = key.create_signature(message, None)?;
        assert!(key.verify_signature(message, signature.as_ref(), None)?);

        let public_jwk = key.to_jwk_public(None)?;
        let imported_public = Box::<AnyKey>::from_jwk(&public_jwk)?;
        assert!(imported_public.verify_signature(message, signature.as_ref(), None)?);

        let private_jwk = key.to_jwk_secret(None)?;
        let private_jwk = core::str::from_utf8(private_jwk.as_ref()).expect("JWK is UTF-8");
        let imported_private = Box::<AnyKey>::from_jwk(private_jwk)?;
        let imported_signature = imported_private.create_signature(message, None)?;
        assert!(imported_public.verify_signature(message, imported_signature.as_ref(), None)?);

        let thumbprint = key.to_jwk_thumbprint(None)?;
        assert_eq!(thumbprint.len(), 43);
        println!(
            "{}: public/private JWK round trip and signature verification OK",
            alg.as_str()
        );
    }

    Ok(())
}
