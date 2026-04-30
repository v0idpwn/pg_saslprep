defmodule PgSASLprepTest do
  use ExUnit.Case, async: true
  doctest PgSASLprep

  describe "RFC 4013 Section 3 examples" do
    # Mirrors src/test/authentication/t/002_saslprep.pl in the postgres tree.

    test "#1: I<U+00AD>X normalizes to IX (soft hyphen mapped to nothing)" do
      assert PgSASLprep.saslprep("I" <> <<0xC2, 0xAD>> <> "X") == {:ok, "IX"}
    end

    test "#2: 'user' is unchanged" do
      assert PgSASLprep.saslprep("user") == {:ok, "user"}
    end

    test "#3: 'USER' preserves case (does not match #2)" do
      assert PgSASLprep.saslprep("USER") == {:ok, "USER"}
    end

    test "#4a: 'a' is identity" do
      assert PgSASLprep.saslprep("a") == {:ok, "a"}
    end

    test "#4b: <U+00AA> normalizes to 'a' via NFKC" do
      assert PgSASLprep.saslprep(<<0xC2, 0xAA>>) == {:ok, "a"}
    end

    test "#5: <U+2168> normalizes to IX (matches #1)" do
      assert PgSASLprep.saslprep(<<0xE2, 0x85, 0xA8>>) == {:ok, "IX"}
    end

    test "#6: <U+0007> is prohibited" do
      assert PgSASLprep.saslprep(<<0x07>>) == {:error, :prohibited}
    end

    test "#7: <U+0627><U+0031> violates bidi rule" do
      # U+0627 is RandALCat (Arabic), '1' is LCat — mixing is forbidden.
      assert PgSASLprep.saslprep(<<0xD8, 0xA7, 0x31>>) == {:error, :prohibited}
    end
  end

  describe "input validation" do
    test "rejects invalid UTF-8" do
      assert PgSASLprep.saslprep(<<0xFF, 0xFE>>) == {:error, :invalid_utf8}
    end

    test "rejects empty string" do
      assert PgSASLprep.saslprep("") == {:error, :empty}
    end

    test "rejects string that becomes empty after step 1 mapping" do
      # U+00AD soft hyphen alone → mapped to nothing → empty.
      assert PgSASLprep.saslprep(<<0xC2, 0xAD>>) == {:error, :empty}
    end
  end

  describe "step 1 mapping" do
    test "non-ASCII spaces map to U+0020" do
      # U+00A0 NBSP between 'a' and 'b' becomes ASCII space.
      assert PgSASLprep.saslprep("a" <> <<0xC2, 0xA0>> <> "b") == {:ok, "a b"}
    end

    test "soft hyphen U+00AD is dropped" do
      assert PgSASLprep.saslprep("foo" <> <<0xC2, 0xAD>> <> "bar") == {:ok, "foobar"}
    end

    test "zero-width joiner U+200D is dropped" do
      assert PgSASLprep.saslprep("a" <> <<0xE2, 0x80, 0x8D>> <> "b") == {:ok, "ab"}
    end
  end

  describe "step 4 bidi" do
    test "all-RandALCat string is allowed" do
      # U+0627 U+0628 (Arabic alef + bah) — both RandALCat.
      assert PgSASLprep.saslprep(<<0xD8, 0xA7, 0xD8, 0xA8>>) == {:ok, <<0xD8, 0xA7, 0xD8, 0xA8>>}
    end

    test "RandALCat must bracket the string (first and last)" do
      # U+0627 + ASCII space + U+0628: space is neither RandALCat nor LCat,
      # so this hinges only on first/last being RandALCat — passes.
      input = <<0xD8, 0xA7>> <> " " <> <<0xD8, 0xA8>>
      # But ASCII space becomes prohibited (U+0020 is fine, not in prohibited
      # ranges). Result depends on bidi: first and last are RandALCat. Allowed.
      assert PgSASLprep.saslprep(input) == {:ok, input}
    end

    test "RandALCat with LCat present is rejected" do
      # U+0627 (RandALCat) + 'a' (LCat) + U+0628 — must reject due to LCat mix.
      assert PgSASLprep.saslprep(<<0xD8, 0xA7>> <> "a" <> <<0xD8, 0xA8>>) ==
               {:error, :prohibited}
    end

    test "RandALCat first but not last is rejected" do
      # U+0627 ... ASCII '5' at end. '5' is in LCat (per D.2).
      assert PgSASLprep.saslprep(<<0xD8, 0xA7>> <> "5") == {:error, :prohibited}
    end
  end

  describe "step 3 prohibit" do
    test "C0 control U+0001 is prohibited" do
      assert PgSASLprep.saslprep(<<0x01>>) == {:error, :prohibited}
    end

    test "DEL U+007F is prohibited" do
      assert PgSASLprep.saslprep(<<0x7F>>) == {:error, :prohibited}
    end

    test "private use area U+E000 is prohibited" do
      assert PgSASLprep.saslprep(<<0xEE, 0x80, 0x80>>) == {:error, :prohibited}
    end

    test "non-character U+FFFE is prohibited" do
      assert PgSASLprep.saslprep(<<0xEF, 0xBF, 0xBE>>) == {:error, :prohibited}
    end
  end

  describe "scram_normalize/1 (RFC 5802 §5.1 fallback)" do
    test "returns normalized string on success" do
      assert PgSASLprep.scram_normalize(<<0xC2, 0xAA>>) == "a"
    end

    test "returns original input when SASLprep would reject" do
      # Prohibited control character: postgres uses it as-is for SCRAM hashing.
      assert PgSASLprep.scram_normalize(<<0x07>>) == <<0x07>>
    end

    test "returns original input on bidi violation" do
      input = <<0xD8, 0xA7, 0x31>>
      assert PgSASLprep.scram_normalize(input) == input
    end

    test "returns original input on invalid UTF-8" do
      assert PgSASLprep.scram_normalize(<<0xFF, 0xFE>>) == <<0xFF, 0xFE>>
    end

    test "returns original input on empty" do
      assert PgSASLprep.scram_normalize("") == ""
    end
  end

  describe "idempotence" do
    test "successful normalization is idempotent" do
      for input <- ["user", "USER", <<0xC2, 0xAA>>, "I" <> <<0xC2, 0xAD>> <> "X"] do
        {:ok, once} = PgSASLprep.saslprep(input)
        assert PgSASLprep.saslprep(once) == {:ok, once}
      end
    end
  end
end
