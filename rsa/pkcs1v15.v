module rsa

// sign_pkcs1v15 calculates the signature of hashed using
// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.
pub fn sign_pkcs1v15(priv PrivateKey, hash_name string, hashed []u8) ![]u8 {
	return sign_digest(priv.evpkey, hash_name, hashed)
}

// verify_pkcs1v15 verifies an RSA PKCS #1 v1.5 signature.
pub fn verify_pkcs1v15(pubkey PublicKey, hash_name string, hashed []u8, sig []u8) bool {
	return verify_signature(pubkey.evpkey, hash_name, sig, hashed)
}

// encrypt_pkcs1v15 encrypts the given message with RSA and the padding
// scheme from PKCS #1 v1.5.  The message must be no longer than the
// length of the public modulus minus 11 bytes.
pub fn encrypt_pkcs1v15(pubkey PublicKey, msg []u8) ![]u8 {
	return encrypt(pubkey.evpkey, msg)
}

// decrypt_pkcs1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.
pub fn decrypt_pkcs1v15(priv PrivateKey, ciphertext []u8) ![]u8 {
	return decrypt(priv.evpkey, ciphertext)
}
