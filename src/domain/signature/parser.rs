//! Recursive-descent parser for signature expressions.

use super::{
    ast::{Call, Expr, Function, Path, Root, Segment, SortOrder},
    lexer::{ParseError, ParseErrorKind, Spanned, Token, tokenize},
};

const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 512;
const SEPARATORS: &[&str] = &["", ".", ":", ",", ";", "\n", " "];

/// Parses expression source into an AST.
///
/// # Errors
///
/// Returns [`ParseError`] describing the first lexical, syntactic, arity, or
/// resource-bound violation.
pub fn parse(source: &str) -> Result<Expr, ParseError> {
    let tokens = tokenize(source)?;
    let mut parser = Parser {
        tokens,
        position: 0,
        nodes: 0,
        end_offset: source.len(),
    };
    let expression = parser.expression(0)?;
    if let Some(extra) = parser.peek() {
        return Err(parser.unexpected("end of input", Some(extra)));
    }
    Ok(expression)
}

struct Parser {
    tokens: Vec<Spanned>,
    position: usize,
    nodes: usize,
    end_offset: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Spanned> {
        self.tokens.get(self.position)
    }

    fn peek_at(&self, ahead: usize) -> Option<&Spanned> {
        self.tokens.get(self.position + ahead)
    }

    fn next(&mut self) -> Option<Spanned> {
        let token = self.tokens.get(self.position).cloned();
        if token.is_some() {
            self.position += 1;
        }
        token
    }

    fn current_offset(&self) -> usize {
        self.peek()
            .map_or(self.end_offset, |spanned| spanned.offset)
    }

    fn unexpected(&self, expected: &'static str, found: Option<&Spanned>) -> ParseError {
        ParseError {
            offset: found.map_or(self.end_offset, |spanned| spanned.offset),
            kind: ParseErrorKind::UnexpectedToken {
                expected,
                found: found.map_or_else(|| "end of input".to_owned(), |s| s.token.describe()),
            },
        }
    }

    fn expect(&mut self, expected: &Token, description: &'static str) -> Result<(), ParseError> {
        match self.next() {
            Some(spanned) if &spanned.token == expected => Ok(()),
            other => Err(self.unexpected(description, other.as_ref())),
        }
    }

    fn count_node(&mut self) -> Result<(), ParseError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(ParseError {
                offset: self.current_offset(),
                kind: ParseErrorKind::TooManyNodes,
            });
        }
        Ok(())
    }

    fn expression(&mut self, depth: usize) -> Result<Expr, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError {
                offset: self.current_offset(),
                kind: ParseErrorKind::TooDeep,
            });
        }
        self.count_node()?;
        let Some(spanned) = self.next() else {
            return Err(self.unexpected("expression", None));
        };
        match spanned.token {
            Token::Text(value) => Ok(Expr::Literal(value)),
            Token::Identifier(name) => {
                if matches!(
                    self.peek(),
                    Some(Spanned {
                        token: Token::LeftParen,
                        ..
                    })
                ) {
                    self.call(&name, spanned.offset, depth)
                } else {
                    self.path(&name, spanned.offset)
                }
            }
            _ => Err(self.unexpected("expression", Some(&spanned))),
        }
    }

    fn path(&mut self, root_name: &str, offset: usize) -> Result<Expr, ParseError> {
        let root = Root::parse(root_name).ok_or_else(|| ParseError {
            offset,
            kind: ParseErrorKind::UnknownRoot(root_name.to_owned()),
        })?;
        let mut segments = Vec::new();
        loop {
            match self.peek().map(|spanned| &spanned.token) {
                Some(Token::Dot) => {
                    self.next();
                    match self.next() {
                        Some(Spanned {
                            token: Token::Identifier(name),
                            ..
                        }) => segments.push(Segment::Key(name)),
                        other => return Err(self.unexpected("member name", other.as_ref())),
                    }
                }
                Some(Token::LeftBracket) => {
                    self.next();
                    match self.next() {
                        Some(Spanned {
                            token: Token::Text(name),
                            ..
                        }) => segments.push(Segment::Key(name)),
                        Some(Spanned {
                            token: Token::Integer(index),
                            ..
                        }) => segments.push(Segment::Index(index)),
                        other => {
                            return Err(self.unexpected("string or integer index", other.as_ref()));
                        }
                    }
                    self.expect(&Token::RightBracket, "]")?;
                }
                _ => break,
            }
            self.count_node()?;
        }
        Ok(Expr::Path(Path { root, segments }))
    }

    fn call(&mut self, name: &str, offset: usize, depth: usize) -> Result<Expr, ParseError> {
        let function = Function::parse(name).ok_or_else(|| ParseError {
            offset,
            kind: ParseErrorKind::UnknownFunction(name.to_owned()),
        })?;
        self.expect(&Token::LeftParen, "(")?;
        let mut call = Call {
            function,
            arguments: Vec::new(),
            separator: None,
            order: None,
        };
        if matches!(
            self.peek(),
            Some(Spanned {
                token: Token::RightParen,
                ..
            })
        ) {
            self.next();
        } else {
            loop {
                self.argument(&mut call, depth)?;
                match self.next() {
                    Some(Spanned {
                        token: Token::Comma,
                        ..
                    }) => {}
                    Some(Spanned {
                        token: Token::RightParen,
                        ..
                    }) => break,
                    other => return Err(self.unexpected(", or )", other.as_ref())),
                }
            }
        }
        validate_call(&call, offset)?;
        Ok(Expr::Call(call))
    }

    fn argument(&mut self, call: &mut Call, depth: usize) -> Result<(), ParseError> {
        let is_keyword = matches!(
            (self.peek(), self.peek_at(1)),
            (
                Some(Spanned {
                    token: Token::Identifier(_),
                    ..
                }),
                Some(Spanned {
                    token: Token::Colon,
                    ..
                })
            )
        );
        if !is_keyword {
            let argument = self.expression(depth + 1)?;
            call.arguments.push(argument);
            return Ok(());
        }
        let Some(Spanned {
            token: Token::Identifier(keyword),
            offset,
        }) = self.next()
        else {
            return Err(self.unexpected("option name", None));
        };
        self.expect(&Token::Colon, ":")?;
        match keyword.as_str() {
            "separator" if call.function.accepts_separator() => {
                if call.separator.is_some() {
                    return Err(ParseError {
                        offset,
                        kind: ParseErrorKind::DuplicateOption("separator"),
                    });
                }
                match self.next() {
                    Some(Spanned {
                        token: Token::Text(value),
                        offset,
                    }) => {
                        if !SEPARATORS.contains(&value.as_str()) {
                            return Err(ParseError {
                                offset,
                                kind: ParseErrorKind::InvalidSeparator(value),
                            });
                        }
                        call.separator = Some(value);
                    }
                    other => return Err(self.unexpected("separator string", other.as_ref())),
                }
            }
            "order" if call.function.accepts_order() => {
                if call.order.is_some() {
                    return Err(ParseError {
                        offset,
                        kind: ParseErrorKind::DuplicateOption("order"),
                    });
                }
                match self.next() {
                    Some(Spanned {
                        token: Token::Identifier(value),
                        offset,
                    }) => {
                        call.order = Some(SortOrder::parse(&value).ok_or(ParseError {
                            offset,
                            kind: ParseErrorKind::InvalidOrder(value),
                        })?);
                    }
                    other => return Err(self.unexpected("asc or desc", other.as_ref())),
                }
            }
            other => {
                return Err(ParseError {
                    offset,
                    kind: ParseErrorKind::UnexpectedOption(other.to_owned()),
                });
            }
        }
        Ok(())
    }
}

fn validate_call(call: &Call, offset: usize) -> Result<(), ParseError> {
    let (min, max) = call.function.arity();
    let actual = call.arguments.len();
    if actual < min || actual > max {
        return Err(ParseError {
            offset,
            kind: ParseErrorKind::Arity {
                function: call.function.name(),
                min,
                max: (max != usize::MAX).then_some(max),
                actual,
            },
        });
    }
    if call.function.requires_separator() && call.separator.is_none() {
        return Err(ParseError {
            offset,
            kind: ParseErrorKind::MissingOption("separator"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Expr, Function, ParseError, ParseErrorKind, Path, Root, Segment, SortOrder, parse,
    };

    #[test]
    fn parses_the_default_standard_webhooks_payload() -> Result<(), ParseError> {
        let source = r#"concat(
            request.headers["webhook-id"],
            ".",
            request.headers["webhook-timestamp"],
            ".",
            request.raw_body
        )"#;
        let Expr::Call(call) = parse(source)? else {
            return Err(ParseError {
                offset: 0,
                kind: ParseErrorKind::Empty,
            });
        };

        assert_eq!(call.function, Function::Concat);
        assert_eq!(call.arguments.len(), 5);
        assert_eq!(
            call.arguments[0],
            Expr::Path(Path {
                root: Root::Request,
                segments: vec![
                    Segment::Key("headers".to_owned()),
                    Segment::Key("webhook-id".to_owned())
                ],
            })
        );
        assert_eq!(call.arguments[1], Expr::Literal(".".to_owned()));
        Ok(())
    }

    #[test]
    fn keyword_arguments_are_validated_per_function() -> Result<(), ParseError> {
        let Expr::Call(sorted) = parse("sort(request.query.ids, order: desc)")? else {
            return Err(ParseError {
                offset: 0,
                kind: ParseErrorKind::Empty,
            });
        };
        assert_eq!(sorted.order, Some(SortOrder::Descending));

        assert!(matches!(
            parse(r"join(request.raw_body)"),
            Err(ParseError {
                kind: ParseErrorKind::MissingOption("separator"),
                ..
            })
        ));
        assert!(matches!(
            parse(r#"join(separator: "|", request.raw_body)"#),
            Err(ParseError {
                kind: ParseErrorKind::InvalidSeparator(_),
                ..
            })
        ));
        assert!(matches!(
            parse("sha256(request.raw_body, order: asc)"),
            Err(ParseError {
                kind: ParseErrorKind::UnexpectedOption(_),
                ..
            })
        ));
        assert!(matches!(
            parse("sort(request.query.ids, order: sideways)"),
            Err(ParseError {
                kind: ParseErrorKind::InvalidOrder(_),
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn arity_unknown_names_and_trailing_input_are_rejected() {
        assert!(matches!(
            parse("sha256()"),
            Err(ParseError {
                kind: ParseErrorKind::Arity { .. },
                ..
            })
        ));
        assert!(matches!(
            parse("sha256(request.raw_body, secret)"),
            Err(ParseError {
                kind: ParseErrorKind::Arity { .. },
                ..
            })
        ));
        assert!(matches!(
            parse("md5(request.raw_body)"),
            Err(ParseError {
                kind: ParseErrorKind::UnknownFunction(_),
                ..
            })
        ));
        assert!(matches!(
            parse("response.body"),
            Err(ParseError {
                kind: ParseErrorKind::UnknownRoot(_),
                ..
            })
        ));
        assert!(matches!(
            parse("secret secret"),
            Err(ParseError {
                kind: ParseErrorKind::UnexpectedToken { .. },
                ..
            })
        ));
    }

    #[test]
    fn nesting_and_node_counts_are_bounded() {
        let deep = format!("{}request.raw_body{}", "hex(".repeat(40), ")".repeat(40));
        assert!(matches!(
            parse(&deep),
            Err(ParseError {
                kind: ParseErrorKind::TooDeep,
                ..
            })
        ));

        let wide = format!(
            "concat({})",
            std::iter::repeat_n("\"a\"", 600)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(matches!(
            parse(&wide),
            Err(ParseError {
                kind: ParseErrorKind::TooManyNodes,
                ..
            })
        ));
    }

    #[test]
    fn display_round_trips_through_the_parser() -> Result<(), ParseError> {
        let source = r#"join(separator: "\n", sort_keys(request.body, order: asc), request.headers["x-id"], request.body.items[0].id, "lit\"eral")"#;
        let parsed = parse(source)?;
        let rendered = parsed.to_string();
        assert_eq!(parse(&rendered)?, parsed);
        Ok(())
    }
}
