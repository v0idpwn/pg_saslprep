# Ported from PostgreSQL's src/common/saslprep.c.
# Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
# Portions Copyright (c) 1994, The Regents of the University of California
# Released under the PostgreSQL License (see LICENSE).

defmodule PgSASLprep do
  @moduledoc """
  RFC 4013 SASLprep, port of PostgreSQL's `pg_saslprep()`
  (`src/common/saslprep.c`).

  Replicates the postgres behavior, including its deviations from RFC 3454:
  the prohibit and bidi checks run on the pre-NFKC codepoints
  (`saslprep.c:1128, 1160`), and an empty post-mapping result is rejected
  (`saslprep.c:1113-1114`).

      iex> PgSASLprep.saslprep("user")
      {:ok, "user"}

      iex> PgSASLprep.saslprep(<<0xC2, 0xAA>>)
      {:ok, "a"}

      iex> PgSASLprep.saslprep(<<0x07>>)
      {:error, :prohibited}

  See `scram_normalize/1` for the RFC 5802 §5.1 fallback.
  """

  alias PgSASLprep.Tables

  @type error :: :invalid_utf8 | :prohibited | :empty

  # Range membership predicates compiled from Tables. One function head per
  # range; the BEAM lowers the guard chain to a decision tree.

  for {lo, hi} <- Tables.non_ascii_space_ranges() do
    defp non_ascii_space?(cp) when cp >= unquote(lo) and cp <= unquote(hi), do: true
  end

  defp non_ascii_space?(_), do: false

  for {lo, hi} <- Tables.commonly_mapped_to_nothing_ranges() do
    defp mapped_to_nothing?(cp) when cp >= unquote(lo) and cp <= unquote(hi), do: true
  end

  defp mapped_to_nothing?(_), do: false

  for {lo, hi} <- Tables.prohibited_output_ranges() do
    defp prohibited?(cp) when cp >= unquote(lo) and cp <= unquote(hi), do: true
  end

  defp prohibited?(_), do: false

  for {lo, hi} <- Tables.unassigned_codepoint_ranges() do
    defp unassigned?(cp) when cp >= unquote(lo) and cp <= unquote(hi), do: true
  end

  defp unassigned?(_), do: false

  for {lo, hi} <- Tables.rand_alcat_ranges() do
    defp rand_alcat?(cp) when cp >= unquote(lo) and cp <= unquote(hi), do: true
  end

  defp rand_alcat?(_), do: false

  for {lo, hi} <- Tables.lcat_ranges() do
    defp lcat?(cp) when cp >= unquote(lo) and cp <= unquote(hi), do: true
  end

  defp lcat?(_), do: false

  @doc """
  Normalize `input` per RFC 4013 SASLprep.

  Errors:

    * `:invalid_utf8` — input is not valid UTF-8
    * `:empty` — input is empty, or empty after step 1 mapping
    * `:prohibited` — input contains a prohibited or unassigned codepoint,
      or violates the bidi rule
  """
  @spec saslprep(binary()) :: {:ok, binary()} | {:error, error()}
  def saslprep(input) when is_binary(input) do
    # `pg_saslprep` takes `const char *`, so postgres only sees the
    # bytes up to the first NUL. Match that before validating UTF-8.
    [truncated | _] = :binary.split(input, <<0>>)

    if String.valid?(truncated) do
      do_saslprep(truncated)
    else
      {:error, :invalid_utf8}
    end
  end

  @doc """
  Returns `saslprep/1`'s output on success, or `input` unchanged on error.

  Implements the RFC 5802 §5.1 fallback used by `pg_be_scram_build_secret`
  (`src/backend/libpq/auth-scram.c:494-496`).
  """
  @spec scram_normalize(binary()) :: binary()
  def scram_normalize(input) when is_binary(input) do
    case saslprep(input) do
      {:ok, normalized} -> normalized
      {:error, _} -> input
    end
  end

  defp do_saslprep(input) do
    cps = String.to_charlist(input)
    mapped = map_step(cps)

    cond do
      mapped == [] -> {:error, :empty}
      not prohibit_ok?(mapped) -> {:error, :prohibited}
      not bidi_ok?(mapped) -> {:error, :prohibited}
      true -> {:ok, mapped |> List.to_string() |> String.normalize(:nfkc)}
    end
  end

  # saslprep.c:1096-1111
  defp map_step(cps), do: map_step(cps, [])
  defp map_step([], acc), do: :lists.reverse(acc)

  defp map_step([cp | rest], acc) do
    cond do
      non_ascii_space?(cp) -> map_step(rest, [0x20 | acc])
      mapped_to_nothing?(cp) -> map_step(rest, acc)
      true -> map_step(rest, [cp | acc])
    end
  end

  # saslprep.c:1128-1136
  defp prohibit_ok?([]), do: true

  defp prohibit_ok?([cp | rest]) do
    cond do
      prohibited?(cp) -> false
      unassigned?(cp) -> false
      true -> prohibit_ok?(rest)
    end
  end

  # saslprep.c:1159-1187
  defp bidi_ok?(cps) do
    if Enum.any?(cps, &rand_alcat?/1) do
      not Enum.any?(cps, &lcat?/1) and
        rand_alcat?(List.first(cps)) and
        rand_alcat?(List.last(cps))
    else
      true
    end
  end
end
