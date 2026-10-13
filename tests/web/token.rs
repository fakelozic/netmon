//! Checks token generation, display and candidate comparisons.
//! Header authentication belongs to `rules.rs`; this file checks the secret itself.
//! Read `random_tokens_and_comparison` first. Generation requires OS randomness.

use netmon::web::Token;

#[test]
fn random_tokens_and_comparison() {
    let token = Token::generate().expect("OS token source");
    let text = token.to_string();
    assert_eq!(text.len(), 32);
    assert!(
        text.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_ne!(
        text,
        Token::generate().expect("second OS token").to_string()
    );
    assert!(token.matches(&text));
    for index in 0..32 {
        let mut wrong = text.as_bytes().to_vec();
        wrong[index] = if wrong[index] == b'0' { b'1' } else { b'0' };
        assert!(!token.matches(std::str::from_utf8(&wrong).expect("ASCII")));
    }
    for wrong in [
        "".to_owned(),
        text[..31].to_owned(),
        format!("{text}0"),
        "x".repeat(32),
        "µ".repeat(16),
    ] {
        assert!(!token.matches(&wrong));
    }
}
