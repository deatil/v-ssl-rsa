module rsa

import crypto.pem

// msg get hash by openssl mdname string
pub fn hash_msg(msg []u8, hash_name string) ![]u8 {
	return calc_digest_with_mdname(msg, hash_name)
}

pub fn encode_pem(block_type string, data []u8) !string {
	b := pem.Block{
		block_type: block_type
		data:       data
	}

	pem_str := b.encode()!
	return pem_str
}

pub fn rsa_error(msg string) IError {
	mut err_str := ''

	err := get_openssl_error()
	if err != '' {
		err_str = 'OpenSSL error: ${err}: ${msg}'
	} else {
		err_str = msg
	}

	return error(err_str)
}

pub fn print_openssl_error() {
	err := get_openssl_error()
	if err != '' {
		println('OpenSSL error: ${err}')
	}
}

fn get_openssl_error() string {
	err := C.ERR_get_error()
	if err != 0 {
		res := []u8{len: 1050}
		C.ERR_error_string(err, res.data)
		return res.bytestr()
	}

	return ''
}

fn calc_digest_with_mdname(msg []u8, name string) ![]u8 {
	md := get_md_with_mdname(name)!
	hashed := calc_digest_with_md(msg, md)!

	return hashed
}

// calc_digest_with_md get the digest of the msg using md digest algorithm
fn calc_digest_with_md(msg []u8, md &C.EVP_MD) ![]u8 {
	ctx := C.EVP_MD_CTX_new()
	if ctx == 0 {
		C.EVP_MD_CTX_free(ctx)
		return rsa_error('EVP_MD_CTX_new failed')
	}

	mut status := C.EVP_DigestInit(ctx, md)
	if status <= 0 {
		C.EVP_MD_CTX_free(ctx)
		return rsa_error('EVP_DigestInit fails')
	}

	status = C.EVP_DigestUpdate(ctx, msg.data, msg.len)
	if status <= 0 {
		C.EVP_MD_CTX_free(ctx)
		return rsa_error('EVP_DigestUpdate fails')
	}

	size := u32(C.EVP_MD_get_size(md))
	out := []u8{len: int(size)}

	status = C.EVP_DigestFinal(ctx, out.data, &size)
	if status <= 0 {
		C.EVP_MD_CTX_free(ctx)
		return rsa_error('EVP_DigestFinal fails')
	}

	digest := out[..size].clone()

	unsafe { out.free() }
	C.EVP_MD_CTX_free(ctx)

	return digest
}

fn get_md_with_mdname(name string) !&C.EVP_MD {
	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_rsa, 0)
	if pctx == 0 {
		C.EVP_PKEY_CTX_free(pctx)
		return rsa_error('C.EVP_PKEY_CTX_new_id failed')
	}

	libctx := C.EVP_PKEY_CTX_get0_libctx(pctx)
	md := C.EVP_MD_fetch(libctx, name.bytes().data, unsafe { nil })

	return md
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
