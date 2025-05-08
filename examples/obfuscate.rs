use rustfuscator::Obfuscator;

fn main() {
    let original_text = "simple text or password";
    let o = Obfuscator::new("randompassphrase".as_bytes())
        .with_salt_length(6)
        .with_separator(rustfuscator::DEFAULT_SEPARATOR_STR);

    // obfuscate
    match o.obfuscate(original_text) {
        Ok(obfuscated_text) => {
            println!("Obfuscated text: {}", obfuscated_text);

            // unobfuscate
            match o.unobfuscate(&obfuscated_text) {
                Ok(unobfuscated_text) => {
                    println!("Unobfuscated text: {}", unobfuscated_text);
                }
                Err(err) => {
                    println!("Error: {}", err);
                }
            }
        }
        Err(err) => {
            println!("Error: {}", err);
        }
    }
}