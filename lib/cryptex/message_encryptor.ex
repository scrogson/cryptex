defmodule Cryptex.MessageEncryptor do
  @moduledoc ~S"""
  `MessageEncryptor` is a simple way to encrypt values which get stored
  somewhere you don't trust.

  The cipher text and initialization vector are base64 encoded and
  returned to you.

  This can be used in situations similar to the `MessageVerifier`, but where
  you don't want users to be able to determine the value of the payload.

  ## Example

    salt = :crypto.strong_rand_bytes(64)
    key = KeyGenerator.generate("password", salt) # => "\x89\xE0\x156\xAC..."
    msg = "my secret message"
    encrypted_data = MessageEncryptor.encrypt_and_sign(msg, key) # => "NlFBTTMwOUV5UlA1QlNEN2xkY2d6eThYWWh..."
    MessageEncryptor.decrypt_and_verify(encrypted_data, key) # => "my secret message"
  """

  use GenServer

  alias Cryptex.MessageVerifier
  import Cryptex.Serializer

  def new(secret, sign_secret, opts \\ []) do
    opts = opts
    |> Keyword.put_new(:cipher, :aes_cbc256)
    |> Keyword.put_new(:serializer, :elixir)
    {:ok, pid} = GenServer.start_link(__MODULE__, [secret, sign_secret, opts])
    pid
  end

  def encrypt_and_sign(pid, message) do
    GenServer.call(pid, {:encrypt_and_sign, message})
  end

  def decrypt_and_verify(pid, encrypted) do
    GenServer.call(pid, {:decrypt_and_verify, encrypted})
  end

  def init([secret, sign_secret, opts]) do
    state = %{
      secret: secret,
      sign_secret: sign_secret,
      cipher: opts[:cipher],
      serializer: convert_serializer(opts[:serializer])
    }
    {:ok, state}
  end

  def handle_call({:encrypt_and_sign, message}, _from, state) do
    iv = :crypto.strong_rand_bytes(16)

    encrypted = message
    |> state.serializer.encode
    |> pad_message
    |> encrypt(state.cipher, state.secret, iv)

    encrypted = "#{Base.encode64(encrypted)}--#{Base.encode64(iv)}"
    signed = MessageVerifier.generate(state.sign_secret, encrypted, :null)

    {:reply, signed, state}
  end

  def handle_call({:decrypt_and_verify, encrypted}, _from, state) do
    {:ok, verified} = MessageVerifier.verify(state.sign_secret, encrypted, :null)
    [encrypted, iv] = String.split(verified, "--") |> Enum.map(&Base.decode64!/1)

    message = encrypted
    |> decrypt(state.cipher, state.secret, iv)
    |> unpad_message
    |> state.serializer.decode

    {:reply, message, state}
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
    <<msg::[binary, size(msg_size)], _::binary>> = rest
    msg
  end

end
