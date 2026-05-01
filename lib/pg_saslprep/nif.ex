defmodule PgSASLprep.NIF do
  @moduledoc false

  # Wraps the Rust `unicode-normalization` crate's NFKC iterator.
  #
  # Erlang's `unicode_util` (used by `String.normalize/2`) has had several
  # NFKC bugs across OTP versions that diverge from postgres' output. We
  # delegate to the Rust crate, which is the de facto reference.

  use Rustler, otp_app: :pg_saslprep, crate: "pg_saslprep_nif"

  @spec nfkc(String.t()) :: String.t()
  def nfkc(_input), do: :erlang.nif_error(:nif_not_loaded)
end
