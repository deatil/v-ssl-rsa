module rsa

import crypto.sha256

fn test_sign_digest() {
	mut pubkey, prikey := generate_key(4096)!

	msg := 'test-message'.bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	sig := sign_digest(prikey.evpkey, "sha256", digest)!
	assert sig.len > 0

	veri := verify_signature(pubkey.evpkey, "sha256", sig, digest)
	assert true == veri

}

fn test_sign_digest_pss() {
	mut pubkey, prikey := generate_key(2048)!

	mut msg := 'test-message'.bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	sig := sign_digest_pss(prikey.evpkey, "sha256", -1, digest)!
	assert sig.len > 0

	veri := verify_signature_pss(pubkey.evpkey, "sha256", pss_salt_length_auto, sig, digest)
	assert true == veri
}

