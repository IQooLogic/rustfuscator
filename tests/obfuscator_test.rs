#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rustfuscator::{Obfuscator, DEFAULT_SEPARATOR_STR};

    #[test]
    fn test_basic_obfuscation_cycle() {
        let passphrase = b"testPassphrase123";
        let obfuscator = Obfuscator::new(passphrase);

        let original_text = "Hello, World!";
        let obfuscated = obfuscator.obfuscate(original_text).unwrap();

        assert_ne!(obfuscated, original_text, "Obfuscated text should be different from original");

        let unobfuscated = obfuscator.unobfuscate(&obfuscated).unwrap();
        assert_eq!(unobfuscated, original_text);
    }

    #[test]
    fn test_various_inputs() {
        let test_cases = [
            ("empty string", ""),
            ("simple text", "Simple text"),
            ("special chars", "Special chars: !@#$%^&*()"),
            ("unicode", "Unicode: 你好，世界！"),
            ("long text", "Very long text that is more than just a few words and contains multiple sentences. It also has some numbers 12345 and special characters !@#$%."),
        ];

        let obfuscator = Obfuscator::new(b"testPassphrase123");

        for (name, input) in test_cases.iter() {
            let obfuscated = obfuscator.obfuscate(input).unwrap();
            let unobfuscated = obfuscator.unobfuscate(&obfuscated).unwrap();
            assert_eq!(unobfuscated, *input, "Failed for case: {}", name);
        }
    }

    #[test]
    fn test_randomization() {
        let obfuscator = Obfuscator::new(b"testPassphrase123");
        let input = "Same input text";

        let first = obfuscator.obfuscate(input).unwrap();
        let second = obfuscator.obfuscate(input).unwrap();

        assert_ne!(first, second, "Expected different obfuscated outputs for same input");
    }

    #[test]
    fn test_custom_salt_length() {
        let custom_salt_length = 16u8;
        let obfuscator = Obfuscator::new(b"testPassphrase123").with_salt_length(custom_salt_length);

        let obfuscated = obfuscator.obfuscate("Test text").unwrap();

        let parts: Vec<&str> = obfuscated.split(DEFAULT_SEPARATOR_STR).collect();
        assert_eq!(parts.len(), 5, "Expected 5 parts including empty first part");

        let salt_bytes = STANDARD.decode(parts[2]).unwrap();
        assert_eq!(salt_bytes.len(), custom_salt_length as usize, "Salt length mismatch");
    }

    #[test]
    fn test_custom_separator() {
        let custom_separator = "#";
        let obfuscator = Obfuscator::new(b"testPassphrase123").with_separator(custom_separator);

        let input = "Test text";
        let obfuscated = obfuscator.obfuscate(input).unwrap();

        assert!(obfuscated.starts_with(custom_separator), "Expected obfuscated text to start with separator");

        let separator_count = obfuscated.matches(custom_separator).count();
        assert_eq!(separator_count, 4, "Expected 4 separators");

        let parts: Vec<&str> = obfuscated.split(custom_separator).collect();
        assert_eq!(parts.len(), 5, "Expected 5 parts including empty first part");
        assert_eq!(parts[1], "o1", "Expected version o1");

        let unobfuscated = obfuscator.unobfuscate(&obfuscated).unwrap();
        assert_eq!(unobfuscated, input);
    }

    #[test]
    fn test_wrong_passphrase() {
        let original_obfuscator = Obfuscator::new(b"correctPassphrase");
        let wrong_obfuscator = Obfuscator::new(b"wrongPassphrase");

        let input = "Secret message";
        let obfuscated = original_obfuscator.obfuscate(input).unwrap();

        let result = wrong_obfuscator.unobfuscate(&obfuscated);
        assert!(result.is_err(), "Expected error when using wrong passphrase");
    }

    #[test]
    fn test_invalid_obfuscated_text() {
        let obfuscator = Obfuscator::new(b"testPassphrase123");

        let invalid_inputs = [
            "invalid$format$string",
            "$invalid$format",
            "$o1$not$enough$parts",
            "",
            "$o1$not-valid-base64$validiv$validcipher",
        ];

        for input in invalid_inputs.iter() {
            let result = obfuscator.unobfuscate(input);
            assert!(result.is_err(), "Expected error for invalid input: {}", input);
        }
    }

    #[test]
    fn test_unsupported_version() {
        let obfuscator = Obfuscator::new(b"testPassphrase123");
        let invalid_version_text = "$o2$salt$iv$ciphertext";

        let result = obfuscator.unobfuscate(invalid_version_text);
        assert!(result.is_err(), "Expected UnsupportedVersion error");
        match result {
            Err(err) => assert!(format!("{}", err).contains("unsupported")),
            _ => panic!("Expected error"),
        }
    }

    #[test]
    fn test_multiple_options() {
        let custom_salt_length = 16u8;
        let custom_separator = "#";
        let obfuscator = Obfuscator::new(b"testPassphrase123")
            .with_salt_length(custom_salt_length)
            .with_separator(custom_separator);

        let input = "Test with multiple options";
        let obfuscated = obfuscator.obfuscate(input).unwrap();

        assert!(obfuscated.contains(custom_separator), "Expected custom separator in output");

        let parts: Vec<&str> = obfuscated.split(custom_separator).collect();
        let salt_bytes = STANDARD.decode(parts[2]).unwrap();
        assert_eq!(salt_bytes.len(), custom_salt_length as usize, "Salt length mismatch");

        let unobfuscated = obfuscator.unobfuscate(&obfuscated).unwrap();
        assert_eq!(unobfuscated, input);
    }

    #[test]
    #[should_panic(expected = "passphrase must not be empty")]
    fn test_empty_passphrase() {
        Obfuscator::new(&[]);
    }

    #[test]
    #[should_panic(expected = "salt length must not be 0")]
    fn test_zero_salt_length() {
        let _obfuscator = Obfuscator::new(b"test").with_salt_length(0);
    }
}