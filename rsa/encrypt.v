module rsa

fn encrypt(key &C.EVP_PKEY, msg []u8) ![]u8 {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_new failed')
	}

	en := C.EVP_PKEY_encrypt_init(ctx)
	if en != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_encrypt_init failed')
	}

	err := C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_PADDING)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_padding fails')
	}

	outlen := i32(0)
	do := C.EVP_PKEY_encrypt(ctx, &[]u8{}, &outlen, msg.data, msg.len)
	if do <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_encrypt fails to get outlen')
	}

	out := []u8{len: int(outlen)}
	do2 := C.EVP_PKEY_encrypt(ctx, out.data, &outlen, msg.data, msg.len)
	if do2 <= 0 {
		unsafe { out.free() }
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_encrypt fails to encrypt message')
	}

	C.EVP_PKEY_CTX_free(ctx)

	return out
}

fn decrypt(key &C.EVP_PKEY, ciphertext []u8) ![]u8 {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_new failed')
	}

	dinit := C.EVP_PKEY_decrypt_init(ctx)
	if dinit != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_decrypt_init failed')
	}

	err := C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_PADDING)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_padding fails')
	}

	outlen := i32(C.EVP_PKEY_size(key))
	do := C.EVP_PKEY_decrypt(ctx, &[]u8{}, &outlen, ciphertext.data, ciphertext.len)
	if do <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_decrypt fails to get outlen')
	}

	mut outlen2 := i32(C.EVP_PKEY_size(key))
	if outlen2 < outlen {
		outlen2 = outlen
	}
	out := []u8{len: outlen}
	res := C.EVP_PKEY_decrypt(ctx, out.data, &outlen2, ciphertext.data, ciphertext.len)
	if res <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_decrypt fails to decrypt ciphertext')
	}

	C.EVP_PKEY_CTX_free(ctx)
	return out
}

fn encrypt_for_oaep(key &C.EVP_PKEY, hash_name string, mgf_hash_name string, msg []u8, label []u8) ![]u8 {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_new failed')
	}

	en := C.EVP_PKEY_encrypt_init(ctx)
	if en != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_encrypt_init failed')
	}

	mut err := C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_OAEP_PADDING)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_padding fails')
	}

	md := get_md_with_mdname(hash_name)!
	err = C.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_oaep_md fails')
	}

	mgf_md := get_md_with_mdname(mgf_hash_name)!
	err = C.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf_md)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_mgf1_md fails')
	}

	dup_label := C.OPENSSL_memdup(label.data, label.len)
	err = C.EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, dup_label, label.len)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set0_rsa_oaep_label fails')
	}

	outlen := i32(0)
	do := C.EVP_PKEY_encrypt(ctx, &[]u8{}, &outlen, msg.data, msg.len)
	if do <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_encrypt fails to get outlen')
	}

	out := []u8{len: int(outlen)}
	res := C.EVP_PKEY_encrypt(ctx, out.data, &outlen, msg.data, msg.len)
	if res <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_encrypt fails to encrypt message')
	}

	C.EVP_PKEY_CTX_free(ctx)
	return out
}

fn decrypt_for_oaep(key &C.EVP_PKEY, hash_name string, mgf_hash_name string, ciphertext []u8, label []u8) ![]u8 {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_new failed')
	}

	dinit := C.EVP_PKEY_decrypt_init(ctx)
	if dinit != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_decrypt_init failed')
	}

	mut err := C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_OAEP_PADDING)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_padding fails')
	}

	md := get_md_with_mdname(hash_name)!
	err = C.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_oaep_md fails')
	}

	mgf_md := get_md_with_mdname(mgf_hash_name)!
	err = C.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf_md)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_mgf1_md fails')
	}

	dup_label := C.OPENSSL_memdup(label.data, label.len)
	err = C.EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, dup_label, label.len)
	if err <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set0_rsa_oaep_label fails')
	}

	outlen := i32(C.EVP_PKEY_size(key))
	do := C.EVP_PKEY_decrypt(ctx, &[]u8{}, &outlen, ciphertext.data, ciphertext.len)
	if do <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_decrypt fails to get outlen')
	}

	mut outlen2 := i32(C.EVP_PKEY_size(key))
	if outlen2 < outlen {
		outlen2 = outlen
	}
	out := []u8{len: outlen}
	res := C.EVP_PKEY_decrypt(ctx, out.data, &outlen2, ciphertext.data, ciphertext.len)
	if res <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_decrypt fails to decrypt ciphertext')
	}

	C.EVP_PKEY_CTX_free(ctx)
	return out
}

