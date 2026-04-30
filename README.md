# PgSASLprep

Elixir port of PostgreSQL's
[`pg_saslprep()`](https://github.com/postgres/postgres/blob/master/src/common/saslprep.c)
(RFC 4013 SASLprep).

## Usage

```elixir
PgSASLprep.saslprep("user")
#=> {:ok, "user"}

PgSASLprep.saslprep(<<0xC2, 0xAA>>)   # U+00AA, NFKC-mapped to "a"
#=> {:ok, "a"}

PgSASLprep.saslprep(<<0x07>>)
#=> {:error, :prohibited}
```

`scram_normalize/1` returns the prepared string on success and the original
input on error, matching `pg_be_scram_build_secret`
(`auth-scram.c:494-496`) and RFC 5802 §5.1:

```elixir
PgSASLprep.scram_normalize(<<0x07>>)
#=> <<0x07>>
```

## Postgres-specific behavior

The output matches `pg_saslprep`, not RFC 3454 to the letter:

- Prohibit and bidi checks run on pre-NFKC codepoints
  (`saslprep.c:1128, 1160`).
- Empty input, or input that becomes empty after step 1 mapping, is rejected
  (`saslprep.c:1113-1114`).
- The `unassigned_codepoint_ranges` table is frozen at Unicode 3.2 per
  RFC 4013. Do not regenerate from a newer Unicode version — it would change
  accept/reject decisions and break interop.

## Implementation

NFKC is delegated to `String.normalize/2`. The library only ships the six
SASLprep range tables from `saslprep.c:62-960`. Range membership is compiled
to BEAM guard chains at compile time.

## Tests

The default suite is fully offline:

```sh
mix test
```

The integration suite (`test/integration_test.exs`) verifies output byte-for-byte
against a real postgres by setting a password server-side, reading back the
SCRAM secret from `pg_authid.rolpassword`, and reproducing the `StoredKey`
locally from `PgSASLprep.scram_normalize/1` of the same input. It is excluded
by default; enable with `--include integration` and a `DATABASE_URL`:

```sh
docker run -d --name pg_saslprep_test \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 \
  -p 54329:5432 postgres:17

DATABASE_URL=postgres://postgres:postgres@localhost:54329/postgres \
  mix test --include integration
```

## License

PostgreSQL License.
