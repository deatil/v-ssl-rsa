module rsa

import crypto.pem

pub fn print_openssl_error() {
    err := C.ERR_get_error()
    if err != 0 {
		res := []u8{len: 1050}
		C.ERR_error_string(err, res.data)
        println("OpenSSL error: ${res.bytestr()}")
    }
}

pub fn hash_msg(msg []u8, hash_name string) ![]u8 {
	return calc_digest_with_mdname(msg, hash_name)
}

pub fn encode_pem(block_type string, data []u8) !string {
	b := pem.Block{
		block_type: block_type
		data: data
	}
	pem_str := b.encode()!
	return pem_str
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
		return error('EVP_MD_CTX_new failed')
	}

	nt := C.EVP_DigestInit(ctx, md)
	assert nt == 1
	upd := C.EVP_DigestUpdate(ctx, msg.data, msg.len)
	assert upd == 1

	size := u32(C.EVP_MD_get_size(md))
	out := []u8{len: int(size)}

	fin := C.EVP_DigestFinal(ctx, out.data, &size)
	assert fin == 1

	digest := out[..size].clone()

	// cleans up
	unsafe { out.free() }
	C.EVP_MD_CTX_free(ctx)

	return digest
}

fn get_md_with_mdname(name string) !&C.EVP_MD {
	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_rsa, 0)
	if pctx == 0 {
		C.EVP_PKEY_CTX_free(pctx)
		return error('C.EVP_PKEY_CTX_new_id failed')
	}

	libctx := C.EVP_PKEY_CTX_get0_libctx(pctx)
	md := C.EVP_MD_fetch(libctx, name.bytes().data, &[]u8{})

	return md
}

