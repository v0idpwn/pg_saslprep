defmodule PgSASLprep.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/v0idpwn/pg_saslprep"

  def project do
    [
      app: :pg_saslprep,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "PgSASLprep"
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:rustler, "~> 0.34"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:postgrex, "~> 0.17", only: :test},
      {:stream_data, "~> 1.1", only: :test}
    ]
  end

  defp description do
    "Elixir port of PostgreSQL's pg_saslprep() (RFC 4013 SASLprep)."
  end

  defp package do
    [
      maintainers: ["Felipe Stival"],
      licenses: ["PostgreSQL"],
      links: %{"GitHub" => @source_url},
      files:
        ~w(lib native/pg_saslprep_nif/src native/pg_saslprep_nif/Cargo.toml
           mix.exs README.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "PgSASLprep",
      source_url: @source_url,
      source_ref: "v#{@version}"
    ]
  end
end
