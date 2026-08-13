//! NIP-50: Search Capability.
//!
//! Filters may carry a `search` string. The relay maintains a word index of
//! event content: an event matches when at least one query term appears in
//! its content, and the results are ordered by how many terms match
//! (relevance), with the `limit` applied after that ordering.

/// Tokenizes text into lowercase alphanumeric words of length >= 2.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            if current.len() >= 2 {
                words.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if current.len() >= 2 {
        words.push(current);
    }
    words
}

/// Search terms derived from a filter's `search` value.
pub fn terms(search: &str) -> Vec<String> {
    tokenize(search)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer() {
        assert_eq!(tokenize("Hello, World! 123"), vec!["hello", "world", "123"]);
        assert_eq!(tokenize("a bc"), vec!["bc"]);
        assert!(tokenize("").is_empty());
        assert!(tokenize("  !!!  ").is_empty());
    }

    #[test]
    fn terms_lowercase() {
        assert_eq!(terms("Rust Nostr"), vec!["rust", "nostr"]);
    }
}
