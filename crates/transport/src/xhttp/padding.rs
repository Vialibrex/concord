use rand::RngExt;

const CHARSET_BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const AVG_HUFFMAN_BYTES_PER_CHAR_BASE62: f64 = 0.8;
const VALIDATION_TOLERANCE: i64 = 2;

// RFC 7541 appendix B code lengths, as in golang.org/x/net/http2/hpack (BSD-3-Clause).
const HUFFMAN_CODE_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

pub(crate) fn huffman_encode_length(text: &str) -> i64 {
    let bits: u64 = text
        .bytes()
        .map(|b| u64::from(HUFFMAN_CODE_LEN.get(usize::from(b)).copied().unwrap_or(30)))
        .sum();
    i64::try_from(bits.div_ceil(8)).unwrap_or(i64::MAX)
}

fn random_base62(len: usize) -> String {
    let mut rng = rand::rng();
    (0..len)
        .filter_map(|_| CHARSET_BASE62.get(rng.random_range(0..CHARSET_BASE62.len())))
        .map(|b| char::from(*b))
        .collect()
}

fn tokenish(target: i64) -> String {
    let n = ((target as f64) / AVG_HUFFMAN_BYTES_PER_CHAR_BASE62)
        .ceil()
        .max(1.0) as usize;
    let mut text = random_base62(n);
    let mut adjust = 'X';
    for _ in 0..150 {
        let diff = huffman_encode_length(&text) - target;
        if diff.abs() <= VALIDATION_TOLERANCE {
            return text;
        }
        if diff < 0 {
            text.push(adjust);
            adjust = if adjust == 'X' { 'Z' } else { 'X' };
        } else {
            if text.len() <= 1 {
                return text;
            }
            text.pop();
        }
    }
    text
}

pub(crate) fn generate(method: &str, length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    match method {
        "tokenish" => {
            let text = tokenish(i64::try_from(length).unwrap_or(i64::MAX));
            if text.is_empty() {
                "X".repeat(length)
            } else {
                text
            }
        }
        _ => "X".repeat(length),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_x_is_the_default() {
        assert_eq!(generate("", 5), "XXXXX");
        assert_eq!(generate("repeat-x", 3), "XXX");
        assert_eq!(generate("repeat-x", 0), "");
    }

    #[test]
    fn huffman_length_matches_known_values() {
        assert_eq!(huffman_encode_length("www.example.com"), 12);
        assert_eq!(huffman_encode_length("no-cache"), 6);
        assert_eq!(huffman_encode_length("XXXXXXXX"), 8);
    }

    #[test]
    fn tokenish_hits_the_target_on_the_wire() {
        for target in [20, 100, 733, 1000] {
            let padding = generate("tokenish", target);
            let got = huffman_encode_length(&padding);
            assert!(
                (got - target as i64).abs() <= VALIDATION_TOLERANCE,
                "{target} -> {got}"
            );
            assert!(padding.bytes().all(|b| b.is_ascii_alphanumeric()));
        }
    }
}
