//! # text_guard (Sanitizer)
//! 
//! メモリ枯渇攻撃(DoS)、インジェクション、およびWindows予約語などの特定文字列を
//! 無害化するための産業グレードのサニタイザー。
//! すべての入力を NFC 正規化し、制御文字や Bidi 文字を物理的に除去する。

#[cfg(feature = "text")]
use unicode_normalization::UnicodeNormalization;

/// テキストの無害化を行う構造体
pub struct Sanitizer {
    max_len: usize,
}

impl Default for Sanitizer {
    fn default() -> Self {
        Self { max_len: 4096 }
    }
}

impl Sanitizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// 最大入力長を設定する
    pub fn max_len(mut self, len: usize) -> Self {
        self.max_len = len;
        self
    }

    /// 文字列をサニタイズする
    pub fn sanitize(&self, input: &str) -> String {
        // 1. DoS対策: バイト数チェック
        let mut text = if input.len() > self.max_len {
            input[..self.max_len].to_string()
        } else {
            input.to_string()
        };

        // 2. Unicode正規化 (NFC)
        #[cfg(feature = "text")]
        {
            text = text.nfc().collect::<String>();
        }

        // 3. 制御文字、Bidi制御文字、および危険なパスキャラクタの除去
        text = text.chars().filter(|&c| !self.is_forbidden_char(c)).collect();

        // 4. Windows 予約語対策
        text = self.mask_windows_reserved(&text);

        // 5. エッジケース (., ..) の置換
        if text == "." {
            return "file_dot".to_string();
        }
        if text == ".." {
            return "file_dot_dot".to_string();
        }

        text
    }

    /// 除去すべき文字の判定（制御文字、Bidi制御文字、OS予約文字の一部）
    fn is_forbidden_char(&self, c: char) -> bool {
        // 制御文字 (U+0000-U+001F, U+007F)
        if c.is_control() {
            return true;
        }

        // Bidi 制御文字 (U+200E..=U+200F, U+202A..=U+202E, U+2066..=U+2069)
        match c {
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202A}' | '\u{202B}'..='\u{202B}' | 
            '\u{202C}'..='\u{202C}' | '\u{202D}'..='\u{202D}' | '\u{202E}'..='\u{202E}' |
            '\u{2066}'..='\u{2069}' => return true,
            _ => {}
        }

        // パスとして危険な文字 (OS固有の制約回避)
        // \ / : * ? " < > | \0
        matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }

    /// Windows の予約済みデバイス名をマスクする (CON -> _CON)
    fn mask_windows_reserved(&self, name: &str) -> String {
        let upper = name.to_uppercase();
        let reserved = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];

        if reserved.contains(&upper.as_str()) {
            format!("_{}", name)
        } else {
            name.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_protection() {
        let sanitizer = Sanitizer::new().max_len(5);
        assert_eq!(sanitizer.sanitize("longstring"), "longs");
    }

    #[test]
    fn test_bidi_removal() {
        let sanitizer = Sanitizer::new();
        // evil\u{202E}txt.exe -> eviltxt.exe
        let input = "evil\u{202E}txt.exe";
        let output = sanitizer.sanitize(input);
        assert!(!output.contains('\u{202E}'));
        assert_eq!(output, "eviltxt.exe");
    }

    #[test]
    fn test_windows_reserved() {
        let sanitizer = Sanitizer::new();
        assert_eq!(sanitizer.sanitize("CON"), "_CON");
        assert_eq!(sanitizer.sanitize("com1"), "_com1");
        assert_eq!(sanitizer.sanitize("safe"), "safe");
    }

    #[test]
    fn test_edge_cases() {
        let sanitizer = Sanitizer::new();
        assert_eq!(sanitizer.sanitize("."), "file_dot");
        assert_eq!(sanitizer.sanitize(".."), "file_dot_dot");
    }

    #[test]
    fn test_path_char_removal() {
        let sanitizer = Sanitizer::new();
        assert_eq!(sanitizer.sanitize("file/name.txt"), "filename.txt");
        assert_eq!(sanitizer.sanitize("a<b>c:d*e?f|g"), "abcdefg");
    }
}
