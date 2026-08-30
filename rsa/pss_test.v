module rsa

import crypto.sha256

fn test_sign_pss() {
	mut pubkey, prikey := generate_key(2048)!

	defer {
		prikey.free()
		pubkey.free()
	}

	mut msg := 'test-message'.bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	sig := sign_pss(prikey, digest, PSSOptions{
		salt_leng: -1
		hash_name: 'sha256'
	})!
	assert sig.len > 0

	veri := verify_pss(pubkey, digest, sig, PSSOptions{
		salt_leng: pss_salt_length_auto
		hash_name: 'sha256'
	})
	assert true == veri
}
