module rsa

import crypto.sha256

fn test_sign_pkcs1v15() {
	mut pubkey, prikey := generate_key(4096)!

	msg := 'test-message'.bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	sig := sign_pkcs1v15(prikey, "sha256", digest)!
	assert sig.len > 0

	veri := verify_pkcs1v15(pubkey, "sha256", digest, sig)
	assert true == veri

}

fn test_encrypt_pkcs1v15() {
	mut pubkey, prikey := generate_key(4096)!

	msg := 'test-message'.bytes()

	enmsg := encrypt_pkcs1v15(pubkey, msg)!
	assert enmsg.len > 0

	demsg := decrypt_pkcs1v15(prikey, enmsg)!
	assert msg.bytestr() == demsg.bytestr()

}

fn use_test_encrypt_pkcs1v15(bits int)! {
	mut pubkey, prikey := generate_key(bits)!

	msg := 'test-message'.bytes()

	enmsg := encrypt_pkcs1v15(pubkey, msg)!
	assert enmsg.len > 0

	demsg := decrypt_pkcs1v15(prikey, enmsg)!
	assert msg.bytestr() == demsg.bytestr()

}

fn test_encrypt_pkcs1v15_with_bits() {
	use_test_encrypt_pkcs1v15(512)!
	use_test_encrypt_pkcs1v15(1024)!
	use_test_encrypt_pkcs1v15(2048)!
	use_test_encrypt_pkcs1v15(4098)!
}

