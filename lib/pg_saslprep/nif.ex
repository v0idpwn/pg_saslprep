defmodule PgSASLprep.NIF do
  @moduledoc false

  # Wraps the Rust `unicode-normalization` crate's NFKC iterator.
  #
  # Erlang's `unicode_util` (used by `String.normalize/2`) has had several
  # NFKC bugs across OTP versions that diverge from postgres' output. We
  # delegate to the Rust crate, which is the de facto reference.

  mix_config = Mix.Project.config()
  version = mix_config[:version]
  source_url = mix_config[:source_url] || "https://github.com/v0idpwn/pg_saslprep"

  use RustlerPrecompiled,
    otp_app: :pg_saslprep,
    crate: "pg_saslprep_nif",
    base_url: "#{source_url}/releases/download/v#{version}",
    force_build: System.get_env("PG_SASLPREP_BUILD") in ["1", "true"],
    version: version,
    targets: ~w(
      aarch64-apple-darwin
      aarch64-unknown-linux-gnu
      aarch64-unknown-linux-musl
      x86_64-apple-darwin
      x86_64-pc-windows-msvc
      x86_64-unknown-linux-gnu
      x86_64-unknown-linux-musl
    )

  @spec nfkc(String.t()) :: String.t()
  def nfkc(_input), do: :erlang.nif_error(:nif_not_loaded)
end
