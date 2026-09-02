//! Tokenizer for the signature expression language.

use std::fmt;

use thiserror::Error;

/// Largest accepted expression source, in bytes.
pub const MAX_EXPRESSION_BYTES: usize = 4_096;

/// A lexical or syntactic error with its byte offset.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{kind} at byte {offset}")]
pub struct ParseError {
    /// Byte offset into the source at which the problem was detected.
    pub offset: usize,
    /// What went wrong.
    pub kind: ParseErrorKind,
}

/// Classification of expression parse failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseErrorKind {
    /// The source exceeds [`MAX_EXPRESSION_BYTES`].
    TooLong,
    /// The source was empty or whitespace.
    Empty,
    /// A character cannot start any token.
    UnexpectedCharacter(char),
    /// A string literal was not closed.
    UnterminatedString,
    /// A backslash escape is not supported.
    InvalidEscape,
    /// A token appeared where another was required.
    UnexpectedToken {
        /// Human-readable description of what was expected.
        expected: &'static str,
        /// The token that was found, or "end of input".
        found: String,
    },
    /// A function name is not defined.
    UnknownFunction(String),
    /// A block root is not defined.
    UnknownRoot(String),
    /// A keyword argument is not accepted by the function.
    UnexpectedOption(String),
    /// The `order:` keyword must be `asc` or `desc`.
    InvalidOrder(String),
    /// The `separator:` keyword must be one of the documented separators.
    InvalidSeparator(String),
    /// A required keyword argument was omitted.
    MissingOption(&'static str),
    /// A keyword argument was repeated.
    DuplicateOption(&'static str),
    /// The number of positional arguments is outside the function's arity.
    Arity {
        /// Function name.
        function: &'static str,
        /// Inclusive minimum.
        min: usize,
        /// Inclusive maximum, or `None` for unbounded.
        max: Option<usize>,
        /// Actual count.
        actual: usize,
    },
    /// Nesting exceeds the supported depth.
    TooDeep,
    /// The expression contains too many nodes.
    TooManyNodes,
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(formatter, "expression exceeds {MAX_EXPRESSION_BYTES} bytes"),
            Self::Empty => formatter.write_str("expression is empty"),
            Self::UnexpectedCharacter(character) => {
                write!(formatter, "unexpected character {character:?}")
            }
            Self::UnterminatedString => formatter.write_str("unterminated string literal"),
            Self::InvalidEscape => formatter.write_str("invalid string escape"),
            Self::UnexpectedToken { expected, found } => {
                write!(formatter, "expected {expected} but found {found}")
            }
            Self::UnknownFunction(name) => write!(formatter, "unknown function {name}"),
            Self::UnknownRoot(name) => write!(formatter, "unknown block {name}"),
            Self::UnexpectedOption(name) => write!(formatter, "unexpected option {name}"),
            Self::InvalidOrder(value) => {
                write!(formatter, "order must be asc or desc, not {value}")
            }
            Self::InvalidSeparator(value) => {
                write!(formatter, "separator {value:?} is not supported")
            }
            Self::MissingOption(name) => write!(formatter, "missing required option {name}"),
            Self::DuplicateOption(name) => write!(formatter, "option {name} was given twice"),
            Self::Arity {
                function,
                min,
                max,
                actual,
            } => match max {
                Some(max) if max == min => {
                    write!(
                        formatter,
                        "{function} takes {min} argument(s), got {actual}"
                    )
                }
                Some(max) => write!(
                    formatter,
                    "{function} takes {min} to {max} argument(s), got {actual}"
                ),
                None => write!(
                    formatter,
                    "{function} takes at least {min} argument(s), got {actual}"
                ),
            },
            Self::TooDeep => formatter.write_str("expression nesting is too deep"),
            Self::TooManyNodes => formatter.write_str("expression has too many nodes"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Token {
    Identifier(String),
    Text(String),
    Integer(usize),
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    Dot,
    Comma,
    Colon,
}

impl Token {
    pub(super) fn describe(&self) -> String {
        match self {
            Self::Identifier(name) => format!("identifier {name}"),
            Self::Text(_) => "string literal".to_owned(),
            Self::Integer(value) => format!("integer {value}"),
            Self::LeftParen => "(".to_owned(),
            Self::RightParen => ")".to_owned(),
            Self::LeftBracket => "[".to_owned(),
            Self::RightBracket => "]".to_owned(),
            Self::Dot => ".".to_owned(),
            Self::Comma => ",".to_owned(),
            Self::Colon => ":".to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct Spanned {
    pub(super) token: Token,
    pub(super) offset: usize,
}

pub(super) fn tokenize(source: &str) -> Result<Vec<Spanned>, ParseError> {
    if source.len() > MAX_EXPRESSION_BYTES {
        return Err(ParseError {
            offset: 0,
            kind: ParseErrorKind::TooLong,
        });
    }
    let mut tokens = Vec::new();
    let mut characters = source.char_indices().peekable();
    while let Some((offset, character)) = characters.next() {
        let token = match character {
            character if character.is_whitespace() => continue,
            '(' => Token::LeftParen,
            ')' => Token::RightParen,
            '[' => Token::LeftBracket,
            ']' => Token::RightBracket,
            '.' => Token::Dot,
            ',' => Token::Comma,
            ':' => Token::Colon,
            '"' => Token::Text(lex_string(&mut characters, offset)?),
            character if character.is_ascii_digit() => {
                let mut digits = String::from(character);
                while let Some((_, next)) = characters.peek() {
                    if next.is_ascii_digit() {
                        digits.push(*next);
                        characters.next();
                    } else {
                        break;
                    }
                }
                Token::Integer(digits.parse().map_err(|_| ParseError {
                    offset,
                    kind: ParseErrorKind::UnexpectedCharacter(character),
                })?)
            }
            character if character.is_ascii_alphabetic() || character == '_' => {
                let mut name = String::from(character);
                while let Some((_, next)) = characters.peek() {
                    if next.is_ascii_alphanumeric() || matches!(next, '_' | '-') {
                        name.push(*next);
                        characters.next();
                    } else {
                        break;
                    }
                }
                Token::Identifier(name)
            }
            other => {
                return Err(ParseError {
                    offset,
                    kind: ParseErrorKind::UnexpectedCharacter(other),
                });
            }
        };
        tokens.push(Spanned { token, offset });
    }
    if tokens.is_empty() {
        return Err(ParseError {
            offset: 0,
            kind: ParseErrorKind::Empty,
        });
    }
    Ok(tokens)
}

fn lex_string(
    characters: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    start: usize,
) -> Result<String, ParseError> {
    let mut value = String::new();
    loop {
        let Some((offset, character)) = characters.next() else {
            return Err(ParseError {
                offset: start,
                kind: ParseErrorKind::UnterminatedString,
            });
        };
        match character {
            '"' => return Ok(value),
            '\\' => {
                let Some((_, escaped)) = characters.next() else {
                    return Err(ParseError {
                        offset,
                        kind: ParseErrorKind::UnterminatedString,
                    });
                };
                value.push(match escaped {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => lex_unicode_escape(characters, offset)?,
                    _ => {
                        return Err(ParseError {
                            offset,
                            kind: ParseErrorKind::InvalidEscape,
                        });
                    }
                });
            }
            control if control.is_control() && control != '\t' => {
                return Err(ParseError {
                    offset,
                    kind: ParseErrorKind::UnexpectedCharacter(control),
                });
            }
            other => value.push(other),
        }
    }
}

fn lex_unicode_escape(
    characters: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    offset: usize,
) -> Result<char, ParseError> {
    let mut digits = String::with_capacity(4);
    for _ in 0..4 {
        match characters.next() {
            Some((_, digit)) if digit.is_ascii_hexdigit() => digits.push(digit),
            _ => {
                return Err(ParseError {
                    offset,
                    kind: ParseErrorKind::InvalidEscape,
                });
            }
        }
    }
    u32::from_str_radix(&digits, 16)
        .ok()
        .and_then(char::from_u32)
        .ok_or(ParseError {
            offset,
            kind: ParseErrorKind::InvalidEscape,
        })
}

#[cfg(test)]
mod tests {
    use super::{ParseErrorKind, Token, tokenize};

    #[test]
    fn tokenizes_paths_calls_and_escaped_strings() -> Result<(), super::ParseError> {
        let tokens = tokenize(r#"join(separator: "\n", request.headers["x-a"], request.query.b)"#)?
            .into_iter()
            .map(|spanned| spanned.token)
            .collect::<Vec<_>>();

        assert_eq!(tokens[0], Token::Identifier("join".to_owned()));
        assert_eq!(tokens[1], Token::LeftParen);
        assert_eq!(tokens[2], Token::Identifier("separator".to_owned()));
        assert_eq!(tokens[3], Token::Colon);
        assert_eq!(tokens[4], Token::Text("\n".to_owned()));
        assert_eq!(tokens[5], Token::Comma);
        assert_eq!(tokens[7], Token::Dot);
        assert_eq!(tokens[8], Token::Identifier("headers".to_owned()));
        assert_eq!(tokens[9], Token::LeftBracket);
        assert_eq!(tokens[10], Token::Text("x-a".to_owned()));
        Ok(())
    }

    #[test]
    fn rejects_unterminated_strings_and_unknown_characters() {
        assert_eq!(
            tokenize(r#"concat("abc"#).map(|_| ()),
            Err(super::ParseError {
                offset: 7,
                kind: ParseErrorKind::UnterminatedString
            })
        );
        assert!(matches!(
            tokenize("a + b"),
            Err(super::ParseError {
                kind: ParseErrorKind::UnexpectedCharacter('+'),
                ..
            })
        ));
        assert!(matches!(
            tokenize("   "),
            Err(super::ParseError {
                kind: ParseErrorKind::Empty,
                ..
            })
        ));
    }

    #[test]
    fn identifiers_admit_header_style_hyphens_and_indexes_are_integers()
    -> Result<(), super::ParseError> {
        let tokens = tokenize("request.headers.webhook-id[0]")?
            .into_iter()
            .map(|spanned| spanned.token)
            .collect::<Vec<_>>();
        assert_eq!(tokens[4], Token::Identifier("webhook-id".to_owned()));
        assert_eq!(tokens[6], Token::Integer(0));
        Ok(())
    }
}
