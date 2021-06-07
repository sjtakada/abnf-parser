use std::collections::HashMap;
use std::fmt;

/// An individual element in an ABNF rule.
#[derive(PartialEq, Clone)]
pub enum Element {
    /// rulename.
    Rulename(String),
    /// case insensitive string.
    IString(String),
    /// case seisitve string.
    SString(String),
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

impl fmt::Debug for Element {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            Element::Rulename(s) => write!(f, "Element::Rulename({:?}.to_string())", s),
            Element::IString(s) => write!(f, "Element::IString({:?}.to_string())", s),
            Element::SString(s) => write!(f, "Element::SString({:?}.to_string())", s),
            Element::NumberValue(n) => write!(f, "Element::NumberValue({:?})", n),
            Element::ValueRange(t) => write!(f, "Element::ValueRange({:?})", t),
            Element::ValueSequence(v) => write!(f, "Element::ValueSequence(vec!{:?})", v),
            Element::ProseValue(s) => write!(f, "Element::ProseValue({:?}.to_string())", s),
            Element::Sequence(v) => write!(f, "Element::Sequence(vec!{:?})", v),
            Element::Selection(v) => write!(f, "Element::Selection(vec!{:?})", v),
        }
    }
}

/// Repeat.
#[derive(PartialEq, Debug, Clone)]
pub struct Repeat {
    pub min: Option<usize>,
    pub max: Option<usize>,
}

impl Repeat {
    pub fn new(min: Option<usize>, max: Option<usize>) -> Repeat {
        Repeat { min, max }
    }
}

/// Element with repeat.
#[derive(PartialEq, Debug, Clone)]
pub struct Repetition {
    pub repeat: Option<Repeat>,
    pub element: Element,
}

impl Repetition {
    pub fn new(repeat: Option<Repeat>, element: Element) -> Repetition {
        Repetition { repeat, element }
    }
}

/// Rulelist.
pub type Rulelist = HashMap<String, Repetition>;
