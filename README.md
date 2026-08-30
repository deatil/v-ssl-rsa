## V-SSL-RSA 

A RSA library base on openssl for vlang.


### Env

 - Vlang >= 0.5.2
 - OpenSSL >= 3.2.4


### Adding v-ssl-rsa as a dependency

Add the dependency to your project:

```bash
v install deatil.sslrsa
```

or 

```bash
v install --git https://github.com/deatil/v-ssl-rsa
```

The `v-ssl-rsa` can be imported in your application with:

```v
import deatil.sslrsa.rsa
```


### Get Starting

~~~v
module main

import deatil.sslrsa.rsa

fn main() {
	pubkey, prikey := rsa.generate_key(2048)!

	defer {
		prikey.free()
		pubkey.free()
	}

	msg := 'test-message'.bytes()
	digest := rsa.hash_msg(msg, 'sha256')!

	signed := rsa.sign_pkcs1v15(prikey, "sha256", digest)!
    println("sign_pkcs1v15: ${signed}")

	veri := rsa.verify_pkcs1v15(pubkey, "sha256", digest, signed)
	println("verify_pkcs1v15: ${veri}")
}
~~~


### RSA functions

Generate key: 
~~~v
generate_key(bits int) !(PublicKey, PrivateKey)
~~~

PKCS1v15 sign: 
~~~v
sign_pkcs1v15(priv PrivateKey, hash_name string, hashed []u8) ![]u8
~~~

~~~v
verify_pkcs1v15(pubkey PublicKey, hash_name string, hashed []u8, sig []u8) bool
~~~

PKCS1v15 encrypt: 
~~~v
encrypt_pkcs1v15(pubkey PublicKey, msg []u8) ![]u8
~~~

~~~v
decrypt_pkcs1v15(priv PrivateKey, ciphertext []u8) ![]u8
~~~

OAEP encrypt: 
~~~v
encrypt_oaep(pubkey PublicKey, hash_name string, msg []u8, label []u8) ![]u8
~~~

~~~v
decrypt_oaep(priv PrivateKey, hash_name string, ciphertext []u8, label []u8) ![]u8
~~~

PSS sign: 
~~~v
pub struct PSSOptions {
pub:
	salt_leng int
	hash_name string
}
~~~

~~~v
sign_pss(priv PrivateKey, digest []u8, opts PSSOptions) ![]u8
~~~

~~~v
verify_pss(pubkey PublicKey, digest []u8, sig []u8, opts PSSOptions) bool
~~~


### Parse PublicKey

Parse pem key: 
~~~v
privkey_from_string(s string) !PrivateKey

pubkey_from_string(s string) !PublicKey
~~~

Make PCKS1 pem key: 
~~~v
make_privkey_pkcs1_pem(prikey PrivateKey) !string

make_pubkey_pkcs1_pem(pubkey PublicKey) !string
~~~

Make PCKS8 pem key: 
~~~v
make_privkey_pem(prikey PrivateKey) !string

make_pubkey_pem(pubkey PublicKey) !string
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
