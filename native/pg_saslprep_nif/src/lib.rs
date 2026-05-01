use unicode_normalization::UnicodeNormalization;

#[rustler::nif]
fn nfkc(input: &str) -> String {
    input.nfkc().collect()
}

rustler::init!("Elixir.PgSASLprep.NIF");
