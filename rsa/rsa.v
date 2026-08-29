module rsa

const nid_evp_pkey_rsa = C.EVP_PKEY_RSA
const nid_rsa_publickey = C.EVP_PKEY_RSA

// https://docs.openssl.org/3.0/man3/EVP_PKEY_fromdata/#selections
const evp_pkey_keypair = C.EVP_PKEY_KEYPAIR

pub struct PrivateKey {
	// The new high level of keypair opaque
	evpkey &C.EVP_PKEY
}

// PrivateKey.new creates a new key pair. By default, it would create a prime256v1 based key.
// Dont forget to call `.free()` after finish with your key.
pub fn PrivateKey.new(bits int, primes int) !PrivateKey {
	evpkey := C.EVP_PKEY_new()
	pctx := C.EVP_PKEY_CTX_new_id(nid_evp_pkey_rsa, 0)
	if pctx == 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('C.EVP_PKEY_CTX_new_id failed')
	}

	nt := C.EVP_PKEY_keygen_init(pctx)
	if nt <= 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('EVP_PKEY_keygen_init failed')
	}

	C.EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits)
	C.EVP_PKEY_CTX_set_rsa_keygen_primes(pctx, primes)

	// generates keypair
	nr := C.EVP_PKEY_keygen(pctx, &evpkey)
	if nr <= 0 {
		C.EVP_PKEY_free(evpkey)
		C.EVP_PKEY_CTX_free(pctx)
		return error('EVP_PKEY_keygen failed')
	}

	// Cleans up the context
	C.EVP_PKEY_CTX_free(pctx)
	// when using default this function, its using underlying curve key size
	// and discarded opt.fixed_size flag when its not set.
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
	n := C.EVP_PKEY_set_bn_param(pbkey, c'priv', bn)
	assert n == 1
	// cleansup
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


