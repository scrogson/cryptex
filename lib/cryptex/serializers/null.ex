defmodule Cryptex.Serializers.NULL do
  def encode(value), do: value
  def decode(value), do: value
end
