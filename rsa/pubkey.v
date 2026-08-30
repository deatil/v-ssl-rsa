module rsa

pub fn privkey_from_string(s string) !PrivateKey {
	if s.len == 0 {
		return rsa_error('null string was not allowed')
	}

	bo := C.BIO_new(C.BIO_s_mem())
	if bo == 0 {
		C.BIO_free_all(bo)
		return rsa_error('Failed to create BIO_new')
	}

	n := C.BIO_write(bo, s.str, s.len)
	if n <= 0 {
		C.BIO_free_all(bo)
		return rsa_error('BIO_write failed')
	}

	mut evpkey := C.EVP_PKEY_new()

	evpkey = C.PEM_read_bio_PrivateKey(bo, &evpkey, 0, 0)
	if evpkey == 0 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_free(evpkey)
		return rsa_error('Error loading key')
	}

	// Get the NID of this key
	nid := C.EVP_PKEY_base_id(evpkey)
	if nid != nid_rsa_publickey {
		C.BIO_free_all(bo)
		C.EVP_PKEY_free(evpkey)
		return rsa_error('Get an nid of non rsaPublicKey')
	}

	pctx := C.EVP_PKEY_CTX_new(evpkey, 0)
	if pctx == 0 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return rsa_error('EVP_PKEY_CTX_new failed')
	}

	// performs evpkey check
	nck := C.EVP_PKEY_check(pctx)
	if nck != 1 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return rsa_error('EVP_PKEY_check failed')
	}

	C.BIO_free_all(bo)
	C.EVP_PKEY_CTX_free(pctx)

	return PrivateKey{
		evpkey: evpkey
	}
}

pub fn pubkey_from_string(s string) !PublicKey {
	if s.len == 0 {
		return rsa_error('Null length string was not allowed')
	}

	bo := C.BIO_new(C.BIO_s_mem())
	if bo == 0 {
		C.BIO_free_all(bo)
		return rsa_error('Failed to create BIO_new')
	}

	n := C.BIO_write(bo, s.str, s.len)
	if n <= 0 {
		C.BIO_free_all(bo)
		return rsa_error('BIO_write failed')
	}

	mut evpkey := C.EVP_PKEY_new()

	evpkey = C.PEM_read_bio_PUBKEY(bo, &evpkey, 0, 0)
	if evpkey == 0 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_free(evpkey)
		return rsa_error('Error loading key')
	}

	// Get the NID of this key.
	nid := C.EVP_PKEY_base_id(evpkey)
	if nid != nid_rsa_publickey {
		C.BIO_free_all(bo)
		C.EVP_PKEY_free(evpkey)
		return rsa_error('Get an nid of non ecPublicKey')
	}

	pctx := C.EVP_PKEY_CTX_new(evpkey, 0)
	if pctx == 0 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return rsa_error('EVP_PKEY_CTX_new failed')
	}

	// performs public-only evpkey check
	nck := C.EVP_PKEY_public_check(pctx)
	if nck != 1 {
		C.BIO_free_all(bo)
		C.EVP_PKEY_CTX_free(pctx)
		C.EVP_PKEY_free(evpkey)
		return rsa_error('EVP_PKEY_check failed')
	}

	C.BIO_free_all(bo)
	C.EVP_PKEY_CTX_free(pctx)

	return PublicKey{
		evpkey: evpkey
	}
}

// pkcs8 key pem
pub fn make_privkey_pem(prikey PrivateKey) !string {
	bo := C.BIO_new(C.BIO_s_mem())
	if bo == 0 {
		C.BIO_free_all(bo)
		return rsa_error('Failed to create BIO_new')
	}

	kstr := []u8{}
	n := C.PEM_write_bio_PrivateKey(bo, prikey.evpkey, unsafe { nil }, kstr.data, 0,
		unsafe { nil }, unsafe { nil })
	if n <= 0 {
		C.BIO_free_all(bo)
		return rsa_error('PEM_write_bio_PrivateKey failed')
	}

	pem_bytes := bio_to_bytes(bo)!
	return pem_bytes.bytestr()
}

// pkcs8 key pem
pub fn make_pubkey_pem(pubkey PublicKey) !string {
	bo := C.BIO_new(C.BIO_s_mem())
	if bo == 0 {
		C.BIO_free_all(bo)
		return rsa_error('Failed to create BIO_new')
	}

	n := C.PEM_write_bio_PUBKEY(bo, pubkey.evpkey)
	if n <= 0 {
		C.BIO_free_all(bo)
		return rsa_error('PEM_write_bio_PUBKEY failed')
	}

	pem_bytes := bio_to_bytes(bo)!
	return pem_bytes.bytestr()
}

// pkcs1 key pem
pub fn make_privkey_pkcs1_pem(prikey PrivateKey) !string {
	mut buf := &u8(unsafe { nil })
	n := C.i2d_PrivateKey(prikey.evpkey, &buf)
	if n <= 0 {
		C.OPENSSL_free(buf)
		return rsa_error('i2d_PrivateKey failed')
	}

	pem_bytes := []u8{len: int(n)}
	unsafe {
		C.memcpy(&pem_bytes[0], buf, n)
		C.OPENSSL_free(buf)
	}
	return encode_pem('RSA PRIVATE KEY', pem_bytes)
}

// pkcs1 key pem
pub fn make_pubkey_pkcs1_pem(pubkey PublicKey) !string {
	mut buf := &u8(unsafe { nil })
	n := C.i2d_PublicKey(pubkey.evpkey, &buf)
	if n <= 0 {
		C.OPENSSL_free(buf)
		return rsa_error('i2d_PublicKey_bio failed')
	}

	pem_bytes := []u8{len: int(n)}
	unsafe {
		C.memcpy(&pem_bytes[0], buf, n)
		C.OPENSSL_free(buf)
	}
	return encode_pem('RSA PUBLIC KEY', pem_bytes)
}

fn bio_to_bytes(bio &C.BIO) ![]u8 {
	siz := C.BIO_pending(bio)
	if siz < 0 {
		return rsa_error('BIO_pending failed')
	}

	buf := []u8{len: siz}
	status := C.BIO_read(bio, buf.data, siz)
	if status < 0 {
		unsafe { buf.free() }
		return rsa_error('BIO_read failed')
	}

	return buf
}
