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
        ExpectRulename(token: Token) {
            display("Expect Rulename (found {:?})", token)
        }
        ExpectDefinedAs {
            display("Expect 'defined-as'")
        }
        ExpectRules {
            display("Expect rules")
        }
        RuleExist {
            display("Rule already exists")
        }
        RuleNotExist {
            display("Rule does not exist")
        }
        TokenParseError {
            display("Token parse error")
        }
        UnexpectedToken(token: Token) {
            display("Unexpected token {:?}", token)
        }
        ParseIntError(err: std::num::ParseIntError) {
            from()
        }
    }
}
