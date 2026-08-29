module rsa

import encoding.hex
import crypto.sha256
import crypto.sha512

fn from_hex(str string) ![]u8 {
	bytes := hex.decode(str)!
	return bytes
}

fn get_private_key() !PrivateKey {
	prikey_pem := "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtn
SgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0i
cqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhC
PUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsAR
ap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKA
Rdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3
n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAy
MaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9
POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdE
KdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gM
IvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDn
FcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvY
mEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghj
FuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+U
I5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs
2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn
/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNT
OvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86
EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+
hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL0
4aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckb
mDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ry
eBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3
CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+
9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq
-----END RSA PRIVATE KEY-----"

	prikey := privkey_from_string(prikey_pem)!

	return prikey
}

fn test_encrypt_oaep_with_opts_check() {
	prikey := get_private_key()!

	label := 'label-test'.bytes()

	opts := OAEPOptions{
		hash_name: "sha384"
		mgf_hash_name: "sha256"
		label: label
	}

	ciphertext := '8659062a3eb2d44df82c8aa822b60fc330c321d773874e35c5a16772887acd638d6bf5d449be06e278d00b763c5bfe05b347ae7ba884e673245979ad7ca14bd6b232afc24dc09bf122a2921cc8918927b0cec053bcb890c325a854fbe36007c16312118b4f369463b1d512a1a6913cf71d0de7f786f7900dcf2be7229b1f906ef36fd81685fe0939cf8e19a6f3c2e7f78e23670611823fed155117478f5638d1c0a84a5019751f38029e334cce33afd25b2b7c5139dd72827835854361bacfd40aaccba6e80d4488ad9f93dbc3fca01312cf9b66d5ea4480036d3592d7123aeb77794506cb65c67ac08670e2af285aad91e191d6dadfbb203bb2a038efeb3334'
	ct := from_hex(ciphertext)!

	demsg := decrypt_oaep_with_opts(prikey, ct, opts)!
	assert demsg.len > 0
	assert "message-data" == demsg.bytestr()
}

fn test_sign_pkcs1v15_check() {
	prikey := get_private_key()!
	pubkey := prikey.public()!

	msg := 'message-data'.bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	ciphertext := '25d14fe04e66c8da872bc54a80ddd3f36c5de3aa9540efb9475b74f62e1f4112ca22f679dbbb3d74a485facea7ea2efcf4404aa3c52418ec4c6c2e7592f868cb64d07f16576ccea344aeaaf6f365fa982bc83c6c9bd70564789e879ab8a4eba6a561a5f289a20453801f16fc79b2b676c0b23e6b530b673bc7a0aff8c4b4a8148e903e7afd6a871dfc70466b1a031068ae583f883de6c94e1d944b73c6cf87269c9bd14120ead9fca8360f5a247747f42d54935927b9dd0ad25821e5f3f2542b22267de397045bf7429f662020759629f71d12c7f91663bc856724685b67a1cd800f398e7378ed1747830bc94d5240d76f5538d505856a1138ebc613b34acdab'
	sig := from_hex(ciphertext)!

	veri := verify_pkcs1v15(pubkey, "sha256", digest, sig)
	assert true == veri

}

fn test_decrypt_pkcs1v15_check() {
	prikey := get_private_key()!

	ciphertext := '61bfa956b12ee62fa056c819f2980e342d2bac5244dc4775b1fc849f7b56aa66fb01e0b95d9393070e04e82c8b71c5676542cbb981976954b710d7277655f70bcc132d71d5d1a861d549e531808e99f6511f41afda67cdd79b8063a0ad2273f3dee378d7c48d55e361acfa83c9d5de6a6be836d82f6d244a8f7959a5e918bcd3fdde570d2d9e9fc59f1b95a6bb71d81fee909250d40beca28441e35a2bc2ed1a383ea99ff4b39e373a5f422cb41d18bf6532e26010000a04631c26ad939e59622c29a76e966a43cae26d833c4a13e463ffb3bd9d9c37a278acee35be11a57bf6f0c033ac66907a46d841898c6fa98ef3f519b32e1db37c553e9177899773721e'
	ct := from_hex(ciphertext)!

	demsg := decrypt_pkcs1v15(prikey, ct)!
	assert demsg.len > 0
	assert "message-data" == demsg.bytestr()
}

fn test_sign_pss_check() {
	prikey := get_private_key()!
	pubkey := prikey.public()!

	msg := 'message-data'.bytes()

	mut d := sha512.new384()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	opts := PSSOptions{
		salt_leng: pss_salt_length_auto
		hash_name: "sha384"
	}

	ciphertext := '301b1064b0ea6f8f3e4196459e5ccd0bfc77c61bdc62edb8c7287a5ae0944fde45374b8ff242916c0abf26df9bae70c933a37a89094753556f038c7d832bc755cb16f76e6e8c64b714f3efe584c76706123ffedd13926d79c2d6e6287ebc778cb1c4106cce481a654eda35e41a0a435291825cecfe9a3bff3c10a6b6108a1ad3c74e6b0a6129d980802ef47f5f96ef88863d629d7f57191da29a76d85a463cc9ee7f9df9efed535aea79a3da0ae38abb03712d65c6ebb4746c6396dc090f0ceb5b7ef989403a70e89768e52a4f08b7f3b205eefd1be4c45b6178756ca58858f9f1f8a06f5abe0cba640f3278656524872117f05159fb750b95a083c55e11207e'
	sig := from_hex(ciphertext)!

	veri := verify_pss(pubkey, digest, sig, opts)
	assert true == veri
}

fn test_sign_pss_check_fail() {
	prikey := get_private_key()!
	pubkey := prikey.public()!

	msg := 'message-data'.bytes()

	mut d := sha512.new384()
	d.reset()
	d.write(msg)!
	digest := d.sum([])

	opts := PSSOptions{
		salt_leng: pss_salt_length_auto
		hash_name: "sha384"
	}

	ciphertext := '301b1064b0ea6f8f3e4196459e5ccd0b3c77c61bdc62edb8c7287a5ae0944fde45374b8ff242916c0abf26df9bae70c933a37a89094753556f038c7d832bc755cb16f76e6e8c64b714f3efe584c76706123ffedd13926d79c2d6e6287ebc778cb1c4106cce481a654eda35e41a0a435291825cecfe9a3bff3c10a6b6108a1ad3c74e6b0a6129d980802ef47f5f96ef88863d629d7f57191da29a76d85a463cc9ee7f9df9efed535aea79a3da0ae38abb03712d65c6ebb4746c6396dc090f0ceb5b7ef989403a70e89768e52a4f08b7f3b205eefd1be4c45b6178756ca58858f9f1f8a06f5abe0cba640f3278656524872117f05159fb750b95a083c55e11207e'
	sig := from_hex(ciphertext)!

	veri := verify_pss(pubkey, digest, sig, opts)
	assert false == veri
}

fn test_encrypt_oaep_check() {
	prikey := get_private_key()!

	label := 'label-test'.bytes()

	ciphertext := '83c83ccf7d76b89bedacbb415e3a0ae219b1dc5b12ea80899e427d51c0594f35b41dedd20224b6e2e84710c78cb3583646de949423179c6b565da28edd139e042b1e2eb2f0b3220a6de904ce5c41e4e870123b29745ba9cdb2818882152ad1024c00d7a0e270846df027e31b687964b9323efd8238e473964106dbc0b3aac915dc3c7783abb721fd7a47de919633c7c4c2c6f8cd74c2fed2edcaf60236cff36457e1dc4e7a21ee8e7b4584e3cff4433d7d1e260a81e96ef6d8991c6b70ff5421f750a225a30167073e57c3c3d00d033ca4c97658c6f8cf82cf5732e2c634e41d521030c9be4798494004bacb5fe047897ee6effaf482bfc56b463bb369973f12'
	ct := from_hex(ciphertext)!

	demsg := decrypt_oaep(prikey, "sha384", ct, label)!
	assert demsg.len > 0
	assert "message-data" == demsg.bytestr()
}
