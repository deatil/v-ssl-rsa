module rsa

fn use_test_encrypt_oaep(bits int)! {
	mut pubkey, prikey := generate_key(bits)!

	msg := 'test-message'.bytes()
	label := 'test-label'.bytes()

	enmsg := encrypt_oaep(pubkey, "sha256", msg, label)!
	assert enmsg.len > 0

	demsg := decrypt_oaep(prikey, "sha256", enmsg, label)!
	assert msg.bytestr() == demsg.bytestr()

}

fn test_encrypt_oaep_with_bits() {
	// use_test_encrypt_oaep(512)!
	use_test_encrypt_oaep(1024)!
	use_test_encrypt_oaep(2048)!
	use_test_encrypt_oaep(4098)!

}

fn use_test_encrypt_oaep_with_opts(bits int)! {
	mut pubkey, prikey := generate_key(bits)!

	msg := 'test-message'.bytes()
	label := 'test-label'.bytes()

	opts := OAEPOptions{
		hash_name: "sha1"
		mgf_hash_name: "sha256"
		label: label
	}

	enmsg := encrypt_oaep_with_opts(pubkey, msg, opts)!
	assert enmsg.len > 0

	demsg := decrypt_oaep_with_opts(prikey, enmsg, opts)!
	assert msg.bytestr() == demsg.bytestr()

}

fn test_encrypt_oaep_with_opts_with_bits() {
	// use_test_encrypt_oaep_with_opts(512)!
	use_test_encrypt_oaep_with_opts(1024)!
	use_test_encrypt_oaep_with_opts(2048)!
	use_test_encrypt_oaep_with_opts(4098)!

}