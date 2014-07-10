defmodule Cryptex.Serializer do
  def convert_serializer(serializer) do
    case Atom.to_string(serializer) do
      "Elixir." <> _ -> serializer
      reference      -> Module.concat(Cryptex.Serializers, String.upcase(reference))
    end
  end
end
