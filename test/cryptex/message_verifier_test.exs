defmodule Cryptex.MessageVerifierTest do
  use ExUnit.Case, async: true

  alias Cryptex.MessageVerifier, as: MV

  test "generates a signed message" do
    [content, encoded] = String.split MV.generate("secret", :hello), "--"
    assert content |> Base.decode64! |> :erlang.binary_to_term == :hello
    assert byte_size(encoded) == 40
  end

  test "verifies a signed message" do
    signed = MV.generate("secret", :hello)
    assert MV.verify("secret", signed) == {:ok, :hello}
  end

  test "does not verify a signed message if secret changed" do
    signed = MV.generate("secret", :hello)
    assert MV.verify("secreto", signed) == :error
  end

  test "does not verify a tampered message" do
    [_, encoded] = String.split MV.generate("secret", :hello), "--"
    content = :bye |> :erlang.term_to_binary |> Base.encode64
    assert MV.verify("secret", content <> "--" <> encoded) == :error
  end
end
