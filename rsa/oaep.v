module rsa

// OAEPOptions corresponds to options for OAEP decryption.
@[params]
pub struct OAEPOptions {
pub:
	// hash_name is the hash name that will be used when generating the mask.
	hash_name string = 'sha1'

	// mgf_hash_name is the hash name used for MGF1.
	mgf_hash_name string

	// label is an arbitrary byte string that must be equal to the value
	// used when encrypting.
	label []u8
}

// encrypt_oaep_with_opts encrypts the given message with RSA-OAEP using the
// provided options.
pub fn encrypt_oaep_with_opts(pubkey PublicKey, msg []u8, opts OAEPOptions) ![]u8 {
	if opts.mgf_hash_name != '' {
		return encrypt_for_oaep(pubkey.evpkey, opts.hash_name, opts.mgf_hash_name, msg, opts.label)
	}

	return encrypt_for_oaep(pubkey.evpkey, opts.hash_name, opts.hash_name, msg, opts.label)
}

// decrypt_oaep_with_opts decrypts the given message with RSA-OAEP using the
// provided options.
pub fn decrypt_oaep_with_opts(priv PrivateKey, ciphertext []u8, opts OAEPOptions) ![]u8 {
	if opts.mgf_hash_name != '' {
		return decrypt_for_oaep(priv.evpkey, opts.hash_name, opts.mgf_hash_name, ciphertext,
			opts.label)
	}

	return decrypt_for_oaep(priv.evpkey, opts.hash_name, opts.hash_name, ciphertext, opts.label)
}

// encrypt_oaep encrypts the given message with RSA-OAEP.
pub fn encrypt_oaep(pubkey PublicKey, hash_name string, msg []u8, label []u8) ![]u8 {
	return encrypt_for_oaep(pubkey.evpkey, hash_name, hash_name, msg, label)
}

// decrypt_oaep decrypts ciphertext using RSA-OAEP.
pub fn decrypt_oaep(priv PrivateKey, hash_name string, ciphertext []u8, label []u8) ![]u8 {
	return decrypt_for_oaep(priv.evpkey, hash_name, hash_name, ciphertext, label)
}
