defmodule PgSASLprep.PropertyTest do
  @moduledoc """
  Property test asserting that `PgSASLprep.saslprep/1` agrees with
  postgres's own `pg_saslprep()` byte-for-byte across a wide variety of
  inputs.

  Requires:

    * a postgres reachable at `DATABASE_URL` with the `test_saslprep`
      extension installed (see `src/test/modules/test_saslprep` in the
      postgres tree)
    * `mix test --include integration`

  The `test_saslprep(bytea)` SQL function is a thin wrapper around
  `pg_saslprep()`: it returns the SASLprep'd output and a status string
  (`SUCCESS`, `INVALID_UTF8`, `PROHIBITED`). We send bytes, parse the
  result, and assert it matches our Elixir port.

  Postgres treats the input as a NUL-terminated C string, so embedded
  `0x00` bytes truncate the input server-side. Our port must match that
  behavior — the generators include NUL bytes deliberately.
  """
  use ExUnit.Case, async: false
  use ExUnitProperties

  @moduletag :integration
  @moduletag timeout: 120_000

  setup_all do
    url =
      System.get_env("DATABASE_URL") ||
        flunk("DATABASE_URL must be set for integration tests")

    {:ok, conn} = Postgrex.start_link(parse_url(url))

    case Postgrex.query(conn, "CREATE EXTENSION IF NOT EXISTS test_saslprep", []) do
      {:ok, _} ->
        :ok

      {:error, %Postgrex.Error{postgres: %{message: msg}}} ->
        flunk("test_saslprep extension not available: #{msg}")
    end

    {:ok, conn: conn}
  end

  describe "saslprep/1 vs postgres test_saslprep()" do
    property "agrees on random byte sequences", %{conn: conn} do
      check all bytes <- random_bytes(), max_runs: 20_000 do
        assert_matches_postgres(conn, bytes)
      end
    end

    property "agrees on sequences of valid Unicode codepoints", %{conn: conn} do
      check all input <- valid_utf8_string(), max_runs: 30_000 do
        assert_matches_postgres(conn, input)
      end
    end

    property "agrees on codepoints from interesting ranges", %{conn: conn} do
      check all input <- biased_utf8_string(), max_runs: 30_000 do
        assert_matches_postgres(conn, input)
      end
    end
  end

  defp assert_matches_postgres(conn, bytes) do
    {pg_status, pg_output} = run_pg_saslprep(conn, bytes)
    ours = PgSASLprep.saslprep(bytes)

    case {pg_status, ours} do
      {"SUCCESS", {:ok, out}} ->
        assert out == pg_output,
               """
               Output mismatch.
                 input (hex):     #{Base.encode16(bytes)}
                 postgres bytes:  #{Base.encode16(pg_output)}
                 elixir bytes:    #{Base.encode16(out)}
               """

      {"INVALID_UTF8", {:error, :invalid_utf8}} ->
        :ok

      # Postgres maps "empty after step 1" to PROHIBITED; we split it out
      # as :empty. Treat both as equivalent.
      {"PROHIBITED", {:error, reason}} when reason in [:prohibited, :empty] ->
        :ok

      _ ->
        flunk("""
        Status mismatch.
          input (hex):  #{Base.encode16(bytes)}
          postgres:     #{pg_status} #{inspect(pg_output)}
          elixir:       #{inspect(ours)}
        """)
    end
  end

  defp run_pg_saslprep(conn, bytes) do
    %{rows: [[{output, status}]]} =
      Postgrex.query!(conn, "SELECT test_saslprep($1::bytea)", [bytes])

    {status, output}
  end

  # --- Generators --------------------------------------------------------

  # Arbitrary bytes (including NUL and invalid UTF-8 sequences). Length
  # capped to keep the test quick.
  defp random_bytes do
    bind(integer(0..16), fn n ->
      bind(list_of(integer(0..255), length: n), fn bs ->
        constant(:erlang.list_to_binary(bs))
      end)
    end)
  end

  # Strings of valid Unicode codepoints encoded as UTF-8, including NUL.
  # Excludes surrogates U+D800..U+DFFF (not valid UTF-8 codepoints).
  defp valid_utf8_string do
    bind(list_of(unicode_codepoint(), max_length: 12), fn cps ->
      constant(cps |> List.to_string())
    end)
  end

  defp unicode_codepoint do
    one_of([
      integer(0x0000..0xD7FF),
      integer(0xE000..0xFFFD),
      integer(0x10000..0x10FFFF)
    ])
  end

  # Codepoints drawn heavily from the SASLprep tables to stress the
  # mapping, prohibit, and bidi paths. Mixed with ordinary ASCII to
  # exercise transitions.
  defp biased_utf8_string do
    bind(list_of(biased_codepoint(), min_length: 1, max_length: 10), fn cps ->
      constant(cps |> List.to_string())
    end)
  end

  defp biased_codepoint do
    frequency([
      {3, integer(?a..?z)},
      {1, integer(?0..?9)},
      # Non-ASCII space (C.1.2)
      {1, member_of([0xA0, 0x1680, 0x2000, 0x2001, 0x200A, 0x202F, 0x205F, 0x3000])},
      # Mapped to nothing (B.1)
      {1, member_of([0xAD, 0x34F, 0x1806, 0x180B, 0x200B, 0x200C, 0x200D, 0x2060, 0xFE00, 0xFEFF])},
      # NFKC-affected
      {1, member_of([0xAA, 0xB5, 0x2168, 0xFB01, 0xFB02, 0x1D400])},
      # Prohibited (C.*) — includes U+0000 to exercise C-string truncation
      {1, member_of([0x00, 0x07, 0x7F, 0x080, 0x340, 0xE000, 0xFFFE, 0xFFFF, 0xFDD0])},
      # RandALCat (Arabic, Hebrew)
      {1, integer(0x0590..0x05FF)},
      {1, integer(0x0600..0x06FF)},
      # LCat sample
      {1, member_of([?a, ?A, 0x00C0, 0x0100])}
    ])
  end

  # --- URL parsing -------------------------------------------------------

  defp parse_url(url) do
    %URI{userinfo: userinfo, host: host, port: port, path: "/" <> database} = URI.parse(url)

    {username, password} =
      case String.split(userinfo || "postgres", ":", parts: 2) do
        [u, p] -> {u, p}
        [u] -> {u, nil}
      end

    [hostname: host, port: port || 5432, username: username, database: database]
    |> then(&if(password, do: Keyword.put(&1, :password, password), else: &1))
  end
end
