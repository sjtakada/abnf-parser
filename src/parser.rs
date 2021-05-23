//
// ABNF parser - Parse ABNF file and dump rulelist.
//   Copyright (C) 2021 Toshiaki Takada
//

use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;
use std::cell::Cell;

use super::error::*;

/// An individual element in an ABNF rule.
#[derive(PartialEq, Debug, Clone)]
pub enum Element {
    /// rulename.
    Rulename(String),
    /// char-val.
    CharValue(String),
    /// num-val.
    NumberValue(u32),
    /// range of num-val.
    ValueRange((u32, u32)),
    /// sequence of num-val.
    ValueSequence(Vec<u32>),
    /// prose-val.
    ProseValue(String),
    /// concatination.
    Sequence(Vec<Repetition>),
    /// alternation.
    Selection(Vec<Repetition>),
}

/// Repeat.
#[derive(PartialEq, Debug, Clone)]
pub struct Repeat {
    min: Option<usize>,
    max: Option<usize>,
}

impl Repeat {
    pub fn new(min: Option<usize>, max: Option<usize>) -> Repeat {
        Repeat {
            min,
            max
        }
    }
}

/// Element with repeat.
#[derive(PartialEq, Debug, Clone)]
pub struct Repetition {
    repeat: Option<Repeat>,
    element: Element,
}

impl Repetition {
    pub fn new(repeat: Option<Repeat>, element: Element) -> Repetition {
        Repetition {
            repeat,
            element,
        }
    }
}

/// Char Value.
#[derive(PartialEq, Debug)]
pub struct CharValue {
    /// Is case sensitive.
    case: bool,
    /// String value.
    value: String,
}

/// Rulelist.
type Rulelist = HashMap<String, Repetition>;

/// ABNF Token type.
#[derive(PartialEq, Debug)]
pub enum Token {
    Whitespace(String),
    Comment(String),
    Rulename(String),
    DefinedAs,
    Incremental,
    CharValue(String),
    NumberValue(u32),
    ValueRange((u32, u32)),
    ValueSequence(Vec<u32>),
    ProseVal(String),
    OptionalBegin,
    OptionalEnd,
    GroupingBegin,
    GroupingEnd,
    Repeat(Repeat),
    Separator,
    Unknown,
}

// Parser, to keep state while parsing.
pub struct Parser {
    /// Input string.
    input: String,
    /// Cursor position in bytes from the beginning.
    pos: Cell<usize>,
    /// Line number at cursor.
    line: Cell<usize>,
}

impl Parser {
    /// Constructor.
    pub fn new(s: String) -> Parser {
        Parser {
            input: s,
            pos: Cell::new(0),
            line: Cell::new(0),
        }
    }

    /// Get input string at current position.
    pub fn input(&self) -> &str {
        &self.input[self.pos.get()..]
    }

    /// Return remaining input length.
    pub fn input_len(&self) -> usize {
        self.input.len() - self.pos.get()
    }

    /// Return parser cusor position.
    pub fn pos(&self) -> usize {
        self.pos.get()
    }

    /// Set cursor position.
    pub fn pos_set(&mut self, pos: usize) {
        self.pos.set(self.pos.get() + pos);
    }

    /// Return line number.
    pub fn line(&self) -> usize {
        self.line.get()
    }

    /// Add len to line number.
    pub fn line_add(&self, len: usize) {
        self.line.set(self.line.get() + len);
    }

    /// Get single token and parsed length.
    pub fn get_token(&mut self) -> Result<Token, AbnfParseError> {
        let input = &self.input();
        let token: Token;
        let mut pos: usize = 0;

        if input.starts_with(char::is_whitespace) {
            pos = match input.find(|c: char| !c.is_whitespace()) {
                Some(pos) => pos,
                None => input.len(),
            };
            let l = &input[..pos];
            let v: Vec<&str> = l.matches("\n").collect();
            self.line_add(v.len());

            token = Token::Whitespace(String::from(l));
        } else if input.starts_with(';') {
            pos = match input.find(|c: char| c == '\r' || c == '\n') {
                Some(pos) => pos,
                None => input.len(),
            };

            token = Token::Comment(String::from(&input[1..pos]));
        } else if input.starts_with("=/") {
            pos = 2;
            token = Token::Incremental;
        } else if input.starts_with('=') {
            pos = 1;
            token = Token::DefinedAs;
        } else if input.starts_with('"') {
            let l = &input[1..];
            pos = match l.find(|c: char| c == '"') {
                Some(pos) => pos,
                None => return Err(AbnfParseError::TokenParseError(self.line(), self.pos())),
            };

            token = Token::CharValue(String::from(&l[..pos]));
            pos += 2;
        } else if input.starts_with(char::is_alphabetic) {
            pos = match input.find(|c: char| !c.is_alphanumeric() && c != '-') {
                Some(pos) => pos,
                None => input.len(),
            };

            token = Token::Rulename(String::from(&input[..pos]));
        } else if input.starts_with('%') {
            let mut l = &input[1..];
            if l.starts_with("s") || l.starts_with("i") {
                let _case = if l.starts_with("s") {
                    true
                } else {
                    false
                };

                l = &input[2..];
                if !l.starts_with('"') {
                    return Err(AbnfParseError::TokenParseError(self.line(), self.pos()));
                }

                l = &input[3..];
                pos = match l.find(|c: char| c == '"') {
                    Some(pos) => pos,
                    None => return Err(AbnfParseError::TokenParseError(self.line(), self.pos())),
                };

                token = Token::CharValue(String::from(&l[..pos]));
                pos += 3;
            } else if l.starts_with(|c: char| c == 'b' || c == 'd' || c == 'x') {
                pos = match l.find(char::is_whitespace) {
                    Some(pos) => pos,
                    None => l.len(),
                };

                let radix = if l.starts_with('b') {
                    2
                } else if l.starts_with('d') {
                    10
                } else {
                    16
                };

                l = &l[1..pos];

                if let Some(_) = l.find('-') {
                    let v: Vec<&str> = l.split("-").collect();
                    if v.len() != 2 {
                        return Err(AbnfParseError::TokenParseError(self.line(), self.pos()));
                     }

                    let rbegin = u32::from_str_radix(v[0], radix).unwrap();
                    let rend = u32::from_str_radix(v[1], radix).unwrap();

                    token = Token::ValueRange((rbegin, rend));

                } else if let Some(_) = l.find('.') {
                    let v: Vec<u32> = l.split("-").map(|s| u32::from_str_radix(s, radix).unwrap()).collect();
                    token = Token::ValueSequence(v);
                } else {
                    let val = u32::from_str_radix(l, radix).unwrap();
                    token = Token::NumberValue(val);
                }
            } else {
                return Err(AbnfParseError::TokenParseError(self.line(), self.pos()));
            }
        } else if input.starts_with("<") {
            let l = &input[1..];
            pos = match l.find(|c: char| c == '>') {
                Some(pos) => pos,
                None => return Err(AbnfParseError::TokenParseError(self.line(), self.pos())),
            };
            token = Token::ProseVal(String::from(&input[1..pos + 1]));
            pos += 2;
        } else if input.starts_with("(") {
            token = Token::GroupingBegin;
            pos = 1;
        } else if input.starts_with(")") {
            token = Token::GroupingEnd;
            pos = 1;
        } else if input.starts_with("[") {
            token = Token::OptionalBegin;
            pos = 1;
        } else if input.starts_with("]") {
            token = Token::OptionalEnd;
            pos = 1;
        } else if input.starts_with("/") {
            token = Token::Separator;
            pos = 1;
        } else if input.starts_with(|c: char| (c >= '1' && c <= '9') || c == '*') {
            let mut min: Option<usize> = None;
            let mut max: Option<usize> = None;
            let mut num: usize = 0;
            let mut l = &input[..];

            loop {
                if !l.starts_with(char::is_numeric) {
                    break;
                }

                num *= 10;
                num += l.chars().next().unwrap().to_digit(10).unwrap() as usize;
                pos += 1;

                l = &l[1..];
            }

            if num > 0 {
                min = Some(num);
            }

            if !l.starts_with(|c: char| c == '*') {
                max = min;
            } else {
                l = &l[1..];
                pos += 1;
                num = 0;

                loop {
                    if !l.starts_with(char::is_numeric) {
                        break;
                    }

                    num *= 10;
                    num += l.chars().next().unwrap().to_digit(10).unwrap() as usize;
                    pos += 1;

                    l = &l[1..];
                }
                if num > 0 {
                    max = Some(num);
                }
            }

            token = Token::Repeat(Repeat::new(min, max));
        } else {
            return Err(AbnfParseError::TokenParseError(self.line(), self.pos()))
        }
        self.pos_set(pos);
        Ok(token)
    }

    /// Parser parse entry point.  Return a rulelist.
    pub fn parse(&mut self) -> Result<Rulelist, AbnfParseError> {
        let mut rulelist = Rulelist::new();
        let mut rulename = None;

        while self.input_len() > 0 {
            // 1. find Rulename.
            loop {
                let token = self.get_token()?;
                match token {
                    Token::Whitespace(_) |
                    Token::Comment(_) => {
                        // Do nothing.
                    }
                    Token::Rulename(name) => {
                        rulename.replace(name);
                        break;
                    }
                    _ => return Err(AbnfParseError::ExpectRulename(self.line(), self.pos(), token)),
                }

                if self.input_len() == 0 {
                    return Err(AbnfParseError::ExpectRulename(self.line(), self.pos(), token));
                }
            }

            // 2. find defined-as (=) or Incremental Alternatives(=/).
            loop {
                let token = self.get_token()?;
                match token {
                    Token::Whitespace(_) |
                    Token::Comment(_) => {
                        // Do nothing.
                    }
                    Token::DefinedAs => {
                        let rulename = rulename.take().unwrap();

                        match rulelist.get(&rulename) {
                            Some(_) => return Err(AbnfParseError::RuleExist(self.line(), self.pos())),
                            None => {
                                match self.parse_rule() {
                                    Ok(rep) => rulelist.insert(rulename, rep),
                                    Err(err) => return Err(err),
                                };
                            }
                        }

                        break;
                    }
                    Token::Incremental => {
                        let rulename = rulename.take().unwrap();

                        match rulelist.remove(&rulename) {
                            Some(rep) => {
                                let mut v = match rep.element {
                                    Element::Selection(v) => v,
                                    _ => vec![rep.clone()],
                                };

                                match self.parse_rule() {
                                    // If one or both rep(s) is/are selection, try to merge.
                                    Ok(rep) => {
                                        match rep.element {
                                            Element::Selection(mut w) => v.append(&mut w),
                                            _ => v.push(rep),
                                        }
                                    }
                                    Err(err) => return Err(err),
                                }

                                rulelist.insert(rulename, Repetition::new(None, Element::Selection(v)));
                            }
                            None => return Err(AbnfParseError::RuleNotExist(self.line(), self.pos())),
                        }

                        break;
                    }
                    _ => return Err(AbnfParseError::ExpectDefinedAs(self.line(), self.pos())),
                }

                if self.input_len() == 0 {
                    return Err(AbnfParseError::ExpectDefinedAs(self.line(), self.pos()));
                }
            }
        }

        Ok(rulelist)
    }

    /// Recursively parse input and find rules.
    pub fn parse_rule(&mut self) -> Result<Repetition, AbnfParseError> {
        let mut v: Vec<Repetition> = Vec::new();
        let mut repeat: Option<Repeat> = None;
        let mut separator = false;
        let mut sv: Vec<Repetition> = Vec::new();

        while self.input_len() > 0 {
            let token = self.get_token()?;
            match token {
                Token::Whitespace(ws) => {
                    if is_rule_delimiter(&ws) {
                        break;
                    }
                    continue;
                }
                Token::Comment(_) => {
                    continue;
                }
                Token::Rulename(name) => {
                    v.push(Repetition::new(repeat.take(), Element::Rulename(name)));
                }
                Token::CharValue(val) => {
                    v.push(Repetition::new(repeat.take(), Element::CharValue(val)));
                }
                Token::NumberValue(val) => {
                    v.push(Repetition::new(repeat.take(), Element::NumberValue(val)));
                }
                Token::ValueRange(val) => {
                    v.push(Repetition::new(repeat.take(), Element::ValueRange(val)));
                }
                Token::ValueSequence(val) => {
                    v.push(Repetition::new(repeat.take(), Element::ValueSequence(val)));
                }
                Token::ProseVal(val) => {
                    v.push(Repetition::new(repeat.take(), Element::ProseValue(val)));
                }
                Token::OptionalBegin => {
                    let mut rep = self.parse_rule()?;
                    rep.repeat.replace(Repeat::new(Some(0), Some(1)));
                    v.push(rep);
                }
                Token::OptionalEnd => {
                    break;
                }
                Token::GroupingBegin => {
                    let mut rep = self.parse_rule()?;
                    rep.repeat = repeat.take();
                    v.push(rep);
                }
                Token::GroupingEnd => {
                    break;
                }
                Token::Repeat(r) => {
                    repeat.replace(r);
                }
                Token::Separator => {
                    separator = true;
                    if v.len() == 1 {
                        sv.push(v.pop().unwrap());
                    } else {
                        sv.push(Repetition::new(None, Element::Sequence(v.drain(..).collect())));
                    }
                }
                _ => {
                    return Err(AbnfParseError::UnexpectedToken(self.line(), self.pos(), token));
                }
            }
        }

        if separator {
            if v.len() == 1 {
                sv.push(v.pop().unwrap());
            } else {
                sv.push(Repetition::new(None, Element::Sequence(v.drain(..).collect())));
            }
            Ok(Repetition::new(None, Element::Selection(sv)))
        } else if v.len() == 1 {
            Ok(v.pop().unwrap())
        } else {
            Ok(Repetition::new(None, Element::Sequence(v)))
        }
    }
}

/// Return true if a given line has more than 2 "\n".
fn is_rule_delimiter(input: &str) -> bool {
    let v: Vec<&str> = input.matches("\n").collect();

    if v.len() > 1 {
        true
    } else {
        false
    }
}

/// Open and parse an ABNF definition file.
pub fn parse_file(filename: &str) -> std::io::Result<()> {
    let mut f = File::open(filename)?;
    let mut s = String::new();

    f.read_to_string(&mut s)?;
    let mut parser = Parser::new(s);

    match parser.parse() {
        Ok(rl) => {
            for (k, v) in rl {
                println!("{:?} => {:?}", k, v);
            }
        }
        Err(err) => {
            println!("Error: {:?}", err);
        }
    }

    Ok(())
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_token_1() {
        let str  = "  abc ";
        let mut parser = Parser::new(str.to_string());

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Whitespace("  ".to_string()));

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Rulename("abc".to_string()));

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Whitespace(" ".to_string()));
    }

    #[test]
    pub fn test_token_2() {
        let str = "10*29DIGIT";
        let mut parser = Parser::new(str.to_string());

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Repeat(Repeat::new(Some(10), Some(29))));

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Rulename("DIGIT".to_string()));
    }

    #[test]
    pub fn test_token_3() {
        let str = "(name)";
        let mut parser = Parser::new(str.to_string());

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::GroupingBegin);

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Rulename("name".to_string()));

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::GroupingEnd);
    }

    #[test]
    pub fn test_token_4() {
        let str = "\n\n\nabc\ndef\n\n";
        let mut parser = Parser::new(str.to_string());

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Whitespace("\n\n\n".to_string()));
        assert_eq!(parser.line(), 3);

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Rulename("abc".to_string()));
        assert_eq!(parser.line(), 3);

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Whitespace("\n".to_string()));
        assert_eq!(parser.line(), 4);

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Rulename("def".to_string()));
        assert_eq!(parser.line(), 4);

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Whitespace("\n\n".to_string()));
        assert_eq!(parser.line(), 6);
    }

    #[test]
    pub fn test_invalid_token_1() {
        let str = "   !";
        let mut parser = Parser::new(str.to_string());

        let token = parser.get_token().unwrap();
        assert_eq!(token, Token::Whitespace("   ".to_string()));

        match parser.get_token() {
            Err(AbnfParseError::TokenParseError(0, 3)) => { },
            Err(err) => assert!(false, "{:?}", err),
            _ => { }
        }
    }

    #[test]
    pub fn test_rule_1() {
        let str = r#"1*( rule / (*c-wsp c-nl) )"#;
        let mut parser = Parser::new(str.to_string());
        let rep = Repetition {
            repeat: Some(Repeat { min: Some(1), max: None }),
            element: Element::Selection(
                vec![Repetition { repeat: None, element: Element::Rulename("rule".to_string()) },
                     Repetition { repeat: None,
                                  element: Element::Sequence(
                                      vec![Repetition { repeat: Some(Repeat { min: None, max: None }),
                                                        element: Element::Rulename("c-wsp".to_string()) },
                                           Repetition { repeat: None, element: Element::Rulename("c-nl".to_string()) }])}])
        };
        if let Ok(r) = parser.parse_rule() {
            assert_eq!(r, rep);
        }
    }

    #[test]
    pub fn test_rule_2() {
        let str = r#"rulename defined-as elements c-nl
                                ; continues if next line starts
                                ;  with white space"#;
        let mut parser = Parser::new(str.to_string());
        let rep = Repetition{
            repeat: None,
            element: Element::Sequence(vec![Repetition { repeat: None, element: Element::Rulename("rulename".to_string()) },
                                            Repetition { repeat: None, element: Element::Rulename("defined-as".to_string()) },
                                            Repetition { repeat: None, element: Element::Rulename("elements".to_string()) },
                                            Repetition { repeat: None, element: Element::Rulename("c-nl".to_string()) }])
        };
        if let Ok(r) = parser.parse_rule() {
            assert_eq!(r, rep);
        }
    }

    #[test]
    pub fn test_rule_3() {
        let str = r#"ALPHA *(ALPHA / DIGIT / "-")"#;
        let mut parser = Parser::new(str.to_string());
        let rep = Repetition {
            repeat: None,
            element: Element::Sequence(vec![Repetition { repeat: None, element: Element::Rulename("ALPHA".to_string()) },
                                            Repetition { repeat: Some(Repeat { min: None, max: None }),
                                                         element: Element::Selection(
                                                             vec![Repetition { repeat: None,
                                                                               element: Element::Rulename("ALPHA".to_string()) },
                                                                  Repetition { repeat: None,
                                                                               element: Element::Rulename("DIGIT".to_string()) },
                                                                  Repetition { repeat: None,
                                                                               element: Element::Literal("-".to_string()) }]) }])
        };
        if let Ok(r) = parser.parse_rule() {
            assert_eq!(r, rep);
        }
    }

    #[test]
    pub fn test_rule_4() {
        let str = r#"*c-wsp ("=" / "=/") *c-wsp
                                ; basic rules definition and
                                ;  incremental alternatives"#;
        let mut parser = Parser::new(str.to_string());
        let rep = Repetition {
            repeat: None,
            element: Element::Sequence(
                vec![Repetition { repeat: Some(Repeat { min: None, max: None }),
                                  element: Element::Rulename("c-wsp".to_string()) },
                     Repetition { repeat: None, element: Element::Selection(
                         vec![Repetition { repeat: None, element: Element::Literal("=".to_string()) },
                              Repetition { repeat: None, element: Element::Literal("=/".to_string()) }]) },
                     Repetition { repeat: Some(Repeat { min: None, max: None }),
                                  element: Element::Rulename("c-wsp".to_string()) }])
        };
        if let Ok(r) = parser.parse_rule() {
            assert_eq!(r, rep);
        }
    }

    #[test]
    pub fn test_parse_1() {
        let str = r#"   "Hello world""#;
        let mut parser = Parser::new(str.to_string());
        match parser.parse() {
            Err(AbnfParseError::ExpectRulename(0, 16, _)) => {},
            Err(e) => assert!(false, "Unexpected error {:?}", e),
            Ok(_) => assert!(false, "Not OK"),
        }
    }

    // test 2

    #[test]
    pub fn test_parse_6() {
        let str = r#"
            ruleset  = alt1 / alt2

            ruleset =/ alt3

            ruleset =/ alt4 / alt5
        "#;
        let mut parser = Parser::new(str.to_string());
        match parser.parse() {
            Err(e) => assert!(false, "error {:?}", e),
            Ok(r) => {
                let rep = r.get("ruleset").unwrap();
                assert_eq!(rep, &Repetition {
                    repeat: None,
                    element: Element::Selection(vec![Repetition { repeat: None, element: Element::Rulename("alt1".to_string()) },
                                                     Repetition { repeat: None, element: Element::Rulename("alt2".to_string()) },
                                                     Repetition { repeat: None, element: Element::Rulename("alt3".to_string()) },
                                                     Repetition { repeat: None, element: Element::Rulename("alt4".to_string()) },
                                                     Repetition { repeat: None, element: Element::Rulename("alt5".to_string()) }]) })
            }
        }
    }

    #[test]
    pub fn test_parse_7() {
        let str = r#"
            ruleset  = alt1 

            ruleset =/ alt2 / alt3

            ruleset =/ alt4 / alt5
        "#;
        let mut parser = Parser::new(str.to_string());
        match parser.parse() {
            Err(e) => assert!(false, "error {:?}", e),
            Ok(r) => {
                let rep = r.get("ruleset").unwrap();
                assert_eq!(rep, &Repetition {
                    repeat: None,
                    element: Element::Selection(vec![Repetition { repeat: None, element: Element::Rulename("alt1".to_string()) },
                                                     Repetition { repeat: None, element: Element::Rulename("alt2".to_string()) },
                                                     Repetition { repeat: None, element: Element::Rulename("alt3".to_string()) },
                                                     Repetition { repeat: None, element: Element::Rulename("alt4".to_string()) },
                                                     Repetition { repeat: None, element: Element::Rulename("alt5".to_string()) }]) })
            }
        }
    }
}
