defmodule Cryptex.MessageEncryptor do
  @moduledoc ~S"""
  `MessageEncryptor` is a simple way to encrypt values which get stored
  somewhere you don't trust.

  The cipher text and initialization vector are base64 encoded and
  returned to you.

  This can be used in situations similar to the `MessageVerifier`, but where
  you don't want users to be able to determine the value of the payload.

  ## Example

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
  """

  alias Cryptex.MessageVerifier
  import Cryptex.Serializer

  def new(secret, sign_secret, opts \\ []) do
    opts = opts
    |> Keyword.put_new(:cipher, :aes_cbc256)
    |> Keyword.put_new(:serializer, :elixir)

    %{
      secret: secret,
      sign_secret: sign_secret,
      cipher: opts[:cipher],
      serializer: convert_serializer(opts[:serializer])
    }
  end

  def encrypt_and_sign(encryptor, message) do
    iv = :crypto.strong_rand_bytes(16)

    encrypted = message
    |> encryptor.serializer.encode
    |> pad_message
    |> encrypt(encryptor.cipher, encryptor.secret, iv)

    encrypted = "#{Base.encode64(encrypted)}--#{Base.encode64(iv)}"
    MessageVerifier.generate(encryptor.sign_secret, encrypted, :null)
  end

  def decrypt_and_verify(encryptor, encrypted) do
    case MessageVerifier.verify(encryptor.sign_secret, encrypted, :null) do
      {:ok, verified} ->
        [encrypted, iv] = String.split(verified, "--") |> Enum.map(&Base.decode64!/1)
        message = encrypted
          |> decrypt(encryptor.cipher, encryptor.secret, iv)
          |> unpad_message
          |> encryptor.serializer.decode
      :error -> {:error, :verify_error}
    end
  end

  defp encrypt(message, cipher, secret, iv) do
    :crypto.block_encrypt(cipher, secret, iv, message)
  end

  defp decrypt(encrypted, cipher, secret, iv) do
    :crypto.block_decrypt(cipher, secret, iv, encrypted)
  end

  defp pad_message(msg) do
    bytes_remaining = rem(byte_size(msg) + 1, 16)
    padding_size = if bytes_remaining == 0, do: 0, else: 16 - bytes_remaining
    <<padding_size>> <> msg <> :crypto.strong_rand_bytes(padding_size)
  end

  defp unpad_message(msg) do
    <<padding_size, rest::binary>> = msg
    msg_size = byte_size(rest) - padding_size
    <<msg::binary-size(msg_size), _::binary>> = rest
    msg
  end
end
