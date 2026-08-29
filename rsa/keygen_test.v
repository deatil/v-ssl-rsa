module rsa

fn test_generate_key() {
	{
		mut pubkey, prikey := generate_key(4096)!
		defer {
			prikey.free()
		}

		assert 512 == pubkey.size()
	}

	{
		mut pubkey, prikey := generate_key(1024)!
		defer {
			prikey.free()
		}

		assert 128 == pubkey.size()
	}

	{
		mut pubkey, prikey := generate_key(2048)!
		defer {
			prikey.free()
		}

		assert 256 == pubkey.size()
	}
}
