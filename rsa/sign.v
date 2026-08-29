module rsa

// sign_digest signs the digest with the key. Under the hood, EVP_PKEY_sign() does not
// hash the data to be signed, and therefore is normally used to sign digests.
fn sign_digest(key &C.EVP_PKEY, mdname string, digest []u8) ![]u8 {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_new failed')
	}

	sin := C.EVP_PKEY_sign_init(ctx)
	if sin != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign_init failed')
	}

	mut status := C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_PADDING)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_padding fails')
	}

	md := get_md_with_mdname(mdname)!
	status = C.EVP_PKEY_CTX_set_signature_md(ctx, md)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_signature_md fails')
	}

	siglen := i32(0)
	status = C.EVP_PKEY_sign(ctx, voidptr(0), &siglen, digest.data, digest.len)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign fails to get siglen')
	}

	sig := []u8{len: int(siglen)}
	status = C.EVP_PKEY_sign(ctx, sig.data, &siglen, digest.data, digest.len)
	if status <= 0 {
		unsafe { sig.free() }
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign fails to sign message')
	}

	sig_data := sig[0..siglen].clone()
	unsafe {
		sig.free()
	}

	C.EVP_PKEY_CTX_free(ctx)

	return sig_data
}

// verify_signature verifies the signature for the digest under the provided key.
fn verify_signature(key &C.EVP_PKEY, mdname string, sig []u8, digest []u8) bool {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	vinit := C.EVP_PKEY_verify_init(ctx)
	if vinit != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	mut status := C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_PADDING)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	md := get_md_with_mdname(mdname) or { return false }
	status = C.EVP_PKEY_CTX_set_signature_md(ctx, md)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	res := C.EVP_PKEY_verify(ctx, sig.data, sig.len, digest.data, digest.len)
	if res <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	C.EVP_PKEY_CTX_free(ctx)

	return res == 1
}

// sign_digest signs the digest with the key. Under the hood, EVP_PKEY_sign() does not
// hash the data to be signed, and therefore is normally used to sign digests.
fn sign_digest_pss(key &C.EVP_PKEY, mdname string, saltlen int, digest []u8) ![]u8 {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_new failed')
	}

	sin := C.EVP_PKEY_sign_init(ctx)
	if sin != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign_init failed')
	}

	mut status := C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_PSS_PADDING)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_padding fails')
	}

	status = C.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_rsa_pss_saltlen fails')
	}

	md := get_md_with_mdname(mdname)!
	status = C.EVP_PKEY_CTX_set_signature_md(ctx, md)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_CTX_set_signature_md fails')
	}

	siglen := i32(0)
	status = C.EVP_PKEY_sign(ctx, voidptr(0), &siglen, digest.data, digest.len)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign fails to get siglen')
	}

	sig := []u8{len: int(siglen)}
	status = C.EVP_PKEY_sign(ctx, sig.data, &siglen, digest.data, digest.len)
	if status <= 0 {
		unsafe { sig.free() }
		C.EVP_PKEY_CTX_free(ctx)
		return error('EVP_PKEY_sign fails to sign message')
	}

	sig_data := sig[0..siglen].clone()
	unsafe {
		sig.free()
	}

	C.EVP_PKEY_CTX_free(ctx)

	return sig_data
}

// verify_signature verifies the signature for the digest under the provided key.
fn verify_signature_pss(key &C.EVP_PKEY, mdname string, saltlen int, sig []u8, digest []u8) bool {
	ctx := C.EVP_PKEY_CTX_new(key, 0)
	if ctx == 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	vinit := C.EVP_PKEY_verify_init(ctx)
	if vinit != 1 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	mut status := C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_PSS_PADDING)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	status = C.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	md := get_md_with_mdname(mdname)  or { return false }
	status = C.EVP_PKEY_CTX_set_signature_md(ctx, md)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	res := C.EVP_PKEY_verify(ctx, sig.data, sig.len, digest.data, digest.len)
	if res <= 0 {
		C.EVP_PKEY_CTX_free(ctx)
		return false
	}

	C.EVP_PKEY_CTX_free(ctx)

	return res == 1
}
