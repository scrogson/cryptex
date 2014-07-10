Cryptex
=======

An [Elixir][] library for encrypting/decrypting, signing/verifying data.

[Elixir]: http://elixir-lang.org

## Usage

```elixir
secret_key_base = "072d1e0157c008193fe48a670cce031faa4e..."
encrypted_cookie_salt = "encrypted cookie"
encrypted_signed_cookie_salt = "signed encrypted cookie"

secret = KeyGenerator.generate(secret_key_base, encrypted_cookie_salt)
sign_secret = KeyGenerator.generate(secret_key_base, encrypted_signed_cookie_salt)
encryptor = MessageEncryptor.new(secret, sign_secret)

data = %{current_user: %{name: "José"}}
encrypted = MessageEncryptor.encrypt_and_sign(encryptor, data)
decrypted = MessageEncryptor.decrypt_and_verify(encryptor, encrypted)
decrypted.current_user.name # => "José"
```
