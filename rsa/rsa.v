module rsa

const nid_evp_pkey_rsa = C.EVP_PKEY_RSA
const nid_rsa_publickey = C.EVP_PKEY_RSA

// https://docs.openssl.org/3.0/man3/EVP_PKEY_fromdata/#selections
const evp_pkey_keypair = C.EVP_PKEY_KEYPAIR

pub struct PrivateKey {
	// The new high level of keypair opaque
	evpkey &C.EVP_PKEY
}

// PrivateKey.new creates a new key pair.
// Dont forget to call `.free()` after finish with your key.
pub fn PrivateKey.new(bits int, primes int) !PrivateKey {
	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_rsa, 0)
	if pctx == 0 {
		C.EVP_PKEY_CTX_free(pctx)
		return rsa_error('EVP_PKEY_CTX_new_id failed')
	}

	mut status := i32(0)

	status = C.EVP_PKEY_keygen_init(pctx)
	if status <= 0 {
		C.EVP_PKEY_CTX_free(pctx)
		return rsa_error('EVP_PKEY_keygen_init failed')
	}

	C.EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits)
	C.EVP_PKEY_CTX_set_rsa_keygen_primes(pctx, primes)

	evpkey := C.EVP_PKEY_new()

	status = C.EVP_PKEY_keygen(pctx, &evpkey)
	if status <= 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return rsa_error('EVP_PKEY_keygen failed')
	}

	C.EVP_PKEY_CTX_free(pctx)

	priv_key := PrivateKey{
		evpkey: evpkey
	}

	return priv_key
}

// public gets the PublicKey from private key.
pub fn (pv PrivateKey) public() !PublicKey {
	// Using duplicate key and removes (clears out) priv key
	pbkey := C.EVP_PKEY_dup(pv.evpkey)

	bn := C.BN_new()
	status := C.EVP_PKEY_set_bn_param(pbkey, c'priv', bn)
	if status <= 0 {
		C.BN_free(bn)
		return rsa_error('EVP_PKEY_keygen failed')
	}

	C.BN_free(bn)

	return PublicKey{
		evpkey: pbkey
	}
}

// equal compares two private keys was equal.
pub fn (priv_key PrivateKey) equal(other PrivateKey) bool {
	eq := C.EVP_PKEY_eq(voidptr(priv_key.evpkey), voidptr(other.evpkey))
	return eq == 1
}

// free clears out allocated memory for PrivateKey. Dont use PrivateKey after calling `.free()`
pub fn (pv &PrivateKey) free() {
	C.EVP_PKEY_free(pv.evpkey)
}

// PublicKey represents ECDSA public key for verifying message.
pub struct PublicKey {
	// The new high level of keypair opaque
	evpkey &C.EVP_PKEY
}

// equal compares two public keys was equal.
pub fn (pub_key PublicKey) equal(other PublicKey) bool {
	eq := C.EVP_PKEY_eq(voidptr(pub_key.evpkey), voidptr(other.evpkey))
	return eq == 1
}

pub fn (pb PublicKey) size() int {
	size := C.EVP_PKEY_get_bits(pb.evpkey)
	return (size + 7) / 8
}

// free clears out allocated memory for PublicKey. Dont use PublicKey after calling `.free()`
pub fn (pb &PublicKey) free() {
	C.EVP_PKEY_free(pb.evpkey)
}
