defmodule PgSASLprep.IntegrationTest do
  @moduledoc """
  Compares `PgSASLprep.scram_normalize/1` output against postgres's own
  SASLprep implementation by deriving the SCRAM `StoredKey` on both sides
  and asserting byte-equality.

  Requires a running postgres reachable at `DATABASE_URL`. Excluded from
  the default `mix test` run; invoke with:

      DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \\
        mix test --include integration

  postgres must be configured with `password_encryption = scram-sha-256`
  (the default since PG14).
  """
  use ExUnit.Case, async: false

  @moduletag :integration

  setup_all do
    url =
      System.get_env("DATABASE_URL") ||
        flunk("DATABASE_URL must be set for integration tests")

    {:ok, conn} = Postgrex.start_link(parse_url(url))
    Postgrex.query!(conn, "SET password_encryption = 'scram-sha-256'", [])
    {:ok, conn: conn}
  end

  # Each vector: a raw password as the user would type it. Postgres applies
  # SASLprep server-side when storing; we apply it client-side via
  # PgSASLprep.scram_normalize/1. The two must derive the same StoredKey.
  #
  # Includes ASCII (no-op SASLprep), NFKC-affected, soft-hyphen-mapped,
  # and non-ASCII-space-mapped inputs.
  @vectors [
    {"ascii", "user"},
    {"ascii_caps", "USER"},
    {"u00aa_to_a", <<0xC2, 0xAA>>},
    {"u2168_to_IX", <<0xE2, 0x85, 0xA8>>},
    {"soft_hyphen", "I" <> <<0xC2, 0xAD>> <> "X"},
    {"nbsp_to_space", "a" <> <<0xC2, 0xA0>> <> "b"},
    {"zwj_dropped", "a" <> <<0xE2, 0x80, 0x8D>> <> "b"},
    {"ligature_fi", <<0xEF, 0xAC, 0x81>> <> "le"},
    {"long_ascii", String.duplicate("p", 64)}
  ]

  for {label, raw} <- @vectors do
    test "matches postgres for #{label}", %{conn: conn} do
      raw = unquote(raw)
      role = unique_role()

      Postgrex.query!(
        conn,
        ~s(CREATE ROLE "#{role}" PASSWORD #{escape_password_literal(raw)}),
        []
      )

      try do
        %{rows: [[stored]]} =
          Postgrex.query!(
            conn,
            "SELECT rolpassword FROM pg_authid WHERE rolname = $1",
            [role]
          )

        {iters, salt, server_stored_key} = parse_scram_secret(stored)

        client_normalized = PgSASLprep.scram_normalize(raw)
        client_stored_key = compute_stored_key(client_normalized, salt, iters)

        assert client_stored_key == server_stored_key,
               """
               StoredKey mismatch for #{unquote(label)}.
               raw input:  #{inspect(raw, base: :hex)}
               normalized: #{inspect(client_normalized, base: :hex)}
               """
      after
        Postgrex.query!(conn, ~s(DROP ROLE "#{role}"), [])
      end
    end
  end

  # CREATE ROLE doesn't accept bind parameters for the password literal, so
  # we have to inline it. Use postgres's E'...' escape-string syntax with
  # \xHH byte escapes for full binary safety.
  defp escape_password_literal(raw) do
    hex = raw |> :binary.bin_to_list() |> Enum.map_join(&:io_lib.format("\\x~2.16.0B", [&1]))
    "E'" <> hex <> "'"
  end

  defp unique_role do
    "saslprep_test_" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)
  end

  # rolpassword has the form: SCRAM-SHA-256$<iters>:<b64 salt>$<b64 stored>:<b64 server>
  # See src/common/scram-common.c:251.
  defp parse_scram_secret("SCRAM-SHA-256$" <> rest) do
    [iters_salt, keys] = String.split(rest, "$", parts: 2)
    [iters, salt_b64] = String.split(iters_salt, ":", parts: 2)
    [stored_b64, _server_b64] = String.split(keys, ":", parts: 2)

    {String.to_integer(iters), Base.decode64!(salt_b64), Base.decode64!(stored_b64)}
  end

  # Per RFC 5802 §3:
  #   SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iters, 32)
  #   ClientKey      = HMAC-SHA256(SaltedPassword, "Client Key")
  #   StoredKey      = SHA256(ClientKey)
  defp compute_stored_key(password, salt, iters) do
    salted = pbkdf2_sha256(password, salt, iters, 32)
    client_key = :crypto.mac(:hmac, :sha256, salted, "Client Key")
    :crypto.hash(:sha256, client_key)
  end

  defp pbkdf2_sha256(password, salt, iters, dklen) do
    blocks_needed = div(dklen + 31, 32)

    1..blocks_needed
    |> Enum.map(&pbkdf2_block(password, salt, iters, &1))
    |> IO.iodata_to_binary()
    |> binary_part(0, dklen)
  end

  defp pbkdf2_block(password, salt, iters, index) do
    initial = :crypto.mac(:hmac, :sha256, password, salt <> <<index::32>>)
    pbkdf2_iterate(password, iters - 1, initial, initial)
  end

  defp pbkdf2_iterate(_password, 0, _prev, acc), do: acc

  defp pbkdf2_iterate(password, n, prev, acc) do
    next = :crypto.mac(:hmac, :sha256, password, prev)
    pbkdf2_iterate(password, n - 1, next, :crypto.exor(next, acc))
  end

  defp parse_url(url) do
    %URI{userinfo: userinfo, host: host, port: port, path: "/" <> database} = URI.parse(url)
    [username, password] = String.split(userinfo, ":", parts: 2)

    [
      hostname: host,
      port: port || 5432,
      username: username,
      password: password,
      database: database
    ]
  end
end
