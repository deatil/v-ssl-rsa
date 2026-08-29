module rsa

// generate_key generates an RSA keypair of the given bit size.
pub fn generate_key(bits int) !(PublicKey, PrivateKey) {
	return generate_multi_prime_key(2, bits)
}

// generate_multi_prime_key generates a multi-prime RSA keypair of the given bit
// size and the given random source, as suggested in [1]. Although the public
// keys are compatible (actually, indistinguishable) from the 2-prime case,
// the private keys are not. Thus it may not be possible to export multi-prime
// private keys in certain formats or to subsequently import them into other
// code.
pub fn generate_multi_prime_key(primes int, bits int) !(PublicKey, PrivateKey) {
	pv := PrivateKey.new(bits, primes)!
	pb := pv.public()!

	return pb, pv
}
