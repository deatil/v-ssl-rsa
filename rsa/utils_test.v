module rsa

import crypto.sha1

fn test_calc_digest_with_mdname() {
	msg := 'test-message'.bytes()

	mut d := sha1.new()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	hashed := calc_digest_with_mdname(msg, 'sha1')!
	assert hashed.len > 0
	assert hashed.hex() == digest.hex()
}

fn test_hash_msg() {
	msg := 'test-message'.bytes()

	mut d := sha1.new()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	hashed := hash_msg(msg, 'sha1')!
	assert hashed.len > 0
	assert hashed.hex() == digest.hex()
}
