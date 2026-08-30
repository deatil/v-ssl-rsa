module rsa

pub const pss_salt_length_equals_hash = C.RSA_PSS_SALTLEN_DIGEST
pub const pss_salt_length_auto = C.RSA_PSS_SALTLEN_AUTO

@[params]
pub struct PSSOptions {
pub:
	salt_leng int = -1
	hash_name string
}

// sign_pss calculates the signature of digest using PSS.
pub fn sign_pss(priv PrivateKey, digest []u8, opts PSSOptions) ![]u8 {
	return sign_digest_pss(priv.evpkey, opts.hash_name, opts.salt_leng, digest)
}

// verify_pss verifies a PSS signature.
pub fn verify_pss(pubkey PublicKey, digest []u8, sig []u8, opts PSSOptions) bool {
	return verify_signature_pss(pubkey.evpkey, opts.hash_name, opts.salt_leng, sig, digest)
}
