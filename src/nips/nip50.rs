//! NIP-50: Search Capability.
//!
//! Filters may carry a `search` string. The relay maintains a word index of
//! event content: an event matches when at least one query term appears in
//! its content, and the results are ordered by relevance — each term is
//! weighted by its inverse document frequency (`1 / (1 + ln df)`, estimated
//! from the word index), so rarer terms dominate the ranking — with the
//! `limit` applied after that ordering. The number of query terms used is
//! capped (see `SEARCH_MAX_TERMS` in the scan engine) so a pathological
//! search string cannot fan out into hundreds of index ranges.

/// Tokenizes text into lowercase alphanumeric words of length >= 2.
///
/// Lowercasing is Unicode-aware (`to_lowercase`) so that the indexed words
/// match the per-event term check in the scan engine, which lowercases the
/// content with the same function: a query for an accented or non-ASCII
/// uppercase term must find the same events the index contains.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            current.extend(ch.to_lowercase());
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

/// Whether any of `terms` appears in `content` as a whole word.
///
/// The word index stores whole words (see [`tokenize`]), so the per-event
/// check must compare whole words too: a substring check would match events
/// the index never returns (e.g. the term "ru" against the indexed word
/// "rust"), making search results depend on whether the word index is
/// enabled. With whole-word matching the index, the non-indexed fallback
/// scan and the live delivery all agree.
pub fn matches_terms(content: &str, terms: &[String]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let words = tokenize(content);
    terms.iter().any(|t| words.iter().any(|w| w == t))
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

    #[test]
    fn whole_word_matching() {
        let terms = super::terms("ru");
        // "ru" must not match "rust" as a substring: the word index stores
        // whole words, so the per-event check must agree with it.
        assert!(!matches_terms("rust", &terms));
        assert!(matches_terms("ru matters", &terms));
        // Any of several terms suffices.
        assert!(matches_terms(
            "only bitcoin",
            &super::terms("nostr bitcoin")
        ));
        assert!(!matches_terms("neither", &super::terms("nostr bitcoin")));
    }
}
