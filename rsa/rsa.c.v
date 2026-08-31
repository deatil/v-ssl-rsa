module rsa

#flag darwin -L/opt/homebrew/opt/openssl/lib
#flag darwin -I/opt/homebrew/opt/openssl/include
#flag darwin -I/usr/local/opt/openssl/include
#flag darwin -L/usr/local/opt/openssl/lib

#flag linux -I/usr/local/include/openssl
#flag linux -L/usr/local/lib64/

#flag openbsd -I/usr/local/include/eopenssl35
#flag openbsd -L/usr/local/lib/eopenssl35 -Wl,-rpath,/usr/local/lib/eopenssl35

// Installed through choco:
#flag windows -IC:/Program Files/OpenSSL-Win64/include
#flag windows -LC:/Program Files/OpenSSL-Win64/lib/VC/x64/MD

// Installed on the CI:
#flag windows -IC:/Program Files/OpenSSL/include
#flag windows -LC:/Program Files/OpenSSL/lib/VC/x64/MD

#flag -I/usr/include/openssl

#flag -lcrypto

#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/rsaerr.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>

fn C.ERR_get_error() u64
fn C.ERR_error_string(e u64, buf &u8) &u8

fn C.OPENSSL_memdup(str &u8, siz int) &u8
fn C.OPENSSL_free(addr voidptr)

@[typedef]
struct C.ENGINE {}

@[typedef]
struct C.EVP_PKEY_CTX {}

fn C.EVP_PKEY_keygen_init(ctx &C.EVP_PKEY_CTX) i32
fn C.EVP_PKEY_CTX_new(&C.EVP_PKEY, &C.ENGINE) &C.EVP_PKEY_CTX
fn C.EVP_PKEY_CTX_new_id(id int, &C.ENGINE) &C.EVP_PKEY_CTX
fn C.EVP_PKEY_keygen(ctx &C.EVP_PKEY_CTX, ppkey &&C.EVP_PKEY) i32
fn C.EVP_PKEY_CTX_set_rsa_keygen_bits(key &C.EVP_PKEY_CTX, bits int) i32
fn C.EVP_PKEY_CTX_set_rsa_keygen_primes(key &C.EVP_PKEY_CTX, primes int) i32
fn C.EVP_PKEY_CTX_set_rsa_padding(ctx &C.EVP_PKEY_CTX, pad_mode int) i32
fn C.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx &C.EVP_PKEY_CTX, saltlen int) i32
fn C.EVP_PKEY_CTX_set_signature_md(ctx &C.EVP_PKEY_CTX, md &C.EVP_MD) i32
fn C.EVP_PKEY_CTX_set_rsa_mgf1_md(key &C.EVP_PKEY_CTX, md &C.EVP_MD) i32
fn C.EVP_PKEY_CTX_set_rsa_oaep_md(key &C.EVP_PKEY_CTX, md &C.EVP_MD) i32
fn C.EVP_PKEY_CTX_set0_rsa_oaep_label(key &C.EVP_PKEY_CTX, label &u8, llen i32) i32

@[typedef]
struct C.BIGNUM {}

fn C.BN_new() &C.BIGNUM
fn C.BN_free(a &C.BIGNUM)

@[typedef]
struct C.EVP_PKEY {}

fn C.EVP_PKEY_new() &C.EVP_PKEY
fn C.EVP_PKEY_free(key &C.EVP_PKEY)
fn C.EVP_PKEY_base_id(key &C.EVP_PKEY) i32
fn C.EVP_PKEY_bits(pkey &C.EVP_PKEY) i32
fn C.EVP_PKEY_size(key &C.EVP_PKEY) i32
fn C.EVP_PKEY_eq(a &C.EVP_PKEY, b &C.EVP_PKEY) i32
fn C.EVP_PKEY_check(ctx &C.EVP_PKEY_CTX) i32
fn C.EVP_PKEY_public_check(ctx &C.EVP_PKEY_CTX) i32
fn C.EVP_PKEY_dup(key &C.EVP_PKEY) &C.EVP_PKEY
fn C.EVP_PKEY_CTX_free(ctx &C.EVP_PKEY_CTX)
fn C.EVP_PKEY_get_bits(pkey &C.EVP_PKEY) i32
fn C.EVP_PKEY_set_bn_param(pkey &C.EVP_PKEY, key_name &char, bn &C.BIGNUM) i32

// no-prehash signing (verifying)
fn C.EVP_PKEY_sign(ctx &C.EVP_PKEY_CTX, sig &u8, siglen &i32, tbs &u8, tbslen i32) i32
fn C.EVP_PKEY_sign_init(ctx &C.EVP_PKEY_CTX) i32
fn C.EVP_PKEY_verify_init(ctx &C.EVP_PKEY_CTX) i32
fn C.EVP_PKEY_verify(ctx &C.EVP_PKEY_CTX, sig &u8, siglen i32, tbs &u8, tbslen i32) i32

fn C.EVP_PKEY_encrypt_init(key &C.EVP_PKEY_CTX) i32
fn C.EVP_PKEY_encrypt(ctx &C.EVP_PKEY_CTX, out &u8, outlen &i32, ins &u8, inslen i32) i32
fn C.EVP_PKEY_decrypt_init(key &C.EVP_PKEY_CTX) i32
fn C.EVP_PKEY_decrypt(ctx &C.EVP_PKEY_CTX, out &u8, outlen &i32, ins &u8, inslen i32) i32

@[typedef]
struct C.EVP_MD_CTX {}

fn C.EVP_MD_CTX_new() &C.EVP_MD_CTX
fn C.EVP_MD_CTX_free(ctx &C.EVP_MD_CTX)

// single shoot digest signing (verifying) routine
fn C.EVP_DigestSign(ctx &C.EVP_MD_CTX, sig &u8, siglen &i32, tbs &u8, tbslen i32) i32
fn C.EVP_DigestVerify(ctx &C.EVP_MD_CTX, sig &u8, siglen i32, tbs &u8, tbslen i32) i32

// Message digest routines
fn C.EVP_DigestInit(ctx &C.EVP_MD_CTX, md &C.EVP_MD) i32
fn C.EVP_DigestUpdate(ctx &C.EVP_MD_CTX, d voidptr, cnt i32) i32
fn C.EVP_DigestFinal(ctx &C.EVP_MD_CTX, md &u8, s &u32) i32

// Recommended hashed signing/verifying routines
fn C.EVP_DigestSignInit(ctx &C.EVP_MD_CTX, pctx &&C.EVP_PKEY_CTX, tipe &C.EVP_MD, e voidptr, pkey &C.EVP_PKEY) i32
fn C.EVP_DigestSignUpdate(ctx &C.EVP_MD_CTX, d voidptr, cnt i32) i32
fn C.EVP_DigestSignFinal(ctx &C.EVP_MD_CTX, sig &u8, siglen &i32) i32
fn C.EVP_DigestVerifyInit(ctx &C.EVP_MD_CTX, pctx &&C.EVP_PKEY_CTX, tipe &C.EVP_MD, e voidptr, pkey &C.EVP_PKEY) i32
fn C.EVP_DigestVerifyUpdate(ctx &C.EVP_MD_CTX, d voidptr, cnt i32) i32
fn C.EVP_DigestVerifyFinal(ctx &C.EVP_MD_CTX, sig &u8, siglen i32) i32

@[typedef]
struct C.EVP_MD {}

fn C.EVP_MD_fetch(ctx &C.OSSL_LIB_CTX, algorithm &u8, properties &u8) &C.EVP_MD
fn C.EVP_MD_get_size(md &C.EVP_MD) i32 // -1 failure

// BIO input output declarations.
@[typedef]
struct C.BIO_METHOD {}

@[typedef]
struct C.EVP_CIPHER {}

@[typedef]
pub struct C.BIO {}

fn C.BIO_new(t &C.BIO_METHOD) &C.BIO
fn C.BIO_free_all(a &C.BIO)
fn C.BIO_s_mem() &C.BIO_METHOD
fn C.BIO_write(b &C.BIO, buf &u8, length i32) i32
fn C.d2i_PUBKEY(k &&C.EVP_PKEY, pp &&u8, length u32) &C.EVP_PKEY
fn C.i2d_PUBKEY_bio(bo &C.BIO, pkey &C.EVP_PKEY) i32
fn C.d2i_PUBKEY_bio(bo &C.BIO, key &&C.EVP_PKEY) &C.EVP_PKEY
fn C.PEM_read_bio_PrivateKey(bp &C.BIO, x &&C.EVP_PKEY, cb voidptr, u voidptr) &C.EVP_PKEY
fn C.PEM_read_bio_PUBKEY(bp &C.BIO, x &&C.EVP_PKEY, cb voidptr, u voidptr) &C.EVP_PKEY
fn C.PEM_write_bio_PUBKEY(bp &C.BIO, x &C.EVP_PKEY) i32
fn C.PEM_write_bio_PrivateKey(out &C.BIO, x &C.EVP_PKEY, enc &C.EVP_CIPHER, kstr &u8, klen i32, cb voidptr, u voidptr) i32
fn C.i2d_PrivateKey(x &C.EVP_PKEY, data &&u8) i32
fn C.i2d_PublicKey(x &C.EVP_PKEY, data &&u8) i32
fn C.BIO_read(bp &C.BIO, data &u8, dlen i32) i32
fn C.BIO_pending(bp &C.BIO) i32

@[typedef]
pub struct C.OSSL_LIB_CTX {}

fn C.EVP_PKEY_CTX_get0_libctx(ctx &C.EVP_PKEY_CTX) &C.OSSL_LIB_CTX
