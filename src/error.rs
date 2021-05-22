//
// ABNF parser - error.
//   Copyright (C) 2021 Toshiaki Takada
//

use quick_error::*;
use super::parser::*;

//
// YANG ABNF Parse Error.
// 
quick_error! {
    #[derive(Debug)]
    pub enum AbnfParseError {
        ExpectRulename(line: usize, pos: usize, token: Token) {
            display("line: {}, pos: {}, Expect Rulename (found {:?})", line, pos, token)
        }
        ExpectDefinedAs(line: usize, pos: usize) {
            display("line: {}, pos: {}, Expect 'defined-as'", line, pos)
        }
        ExpectRules(line: usize, pos: usize) {
            display("line: {}, pos: {}, Expect rules", line, pos)
        }
        TokenParseError(line: usize, pos: usize) {
            display("line: {}, pos: {}, Token parse error", line, pos)
        }
        UnexpectedToken(line: usize, pos: usize, token: Token) {
            display("line: {}, pos: {}, Unepected token {:?}", line, pos, token)
        }
    }
}
