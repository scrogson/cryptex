defmodule Cryptex.Mixfile do
  use Mix.Project

  @description """
  An Elixir library for encrypting/decrypting, signing/verifying data.
  """

  def project do
    [app: :cryptex,
     version: "0.0.1",
     elixir: ">= 0.14.0",
     description: @description,
     package: package]
  end

  def application do
    [applications: []]
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "LICENSE"],
      contributors: ["Sonny Scroggin"],
      licenses: ["MIT"],
      links: [ { "GitHub", "https://github.com/scrogson/cryptex" } ]
    ]
  end
end
