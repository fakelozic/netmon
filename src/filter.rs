//! Evaluates the bounded display-filter language.
//! Capture filtering belongs to live; this parser only selects retained rows.
//! Start with parse, then call Filter::matches for each summary row.
//! A transport protocol can carry another protocol, such as HTTP over TCP.
use crate::decode::{Addr, Proto, Summary};
use crate::{explain::ui, text};

/// One retained row plus optional learned names and application ownership.
/// None means the corresponding label is not available; matching never performs lookups.
pub struct Row<'a> {
    pub summary: &'a Summary,
    pub sentence: &'a str,
    /// Learned source hostname, or None when it has not been resolved passively.
    pub src_name: Option<&'a str>,
    /// Learned destination hostname, or None when unavailable.
    pub dst_name: Option<&'a str>,
    /// Process label, or None when no program is known for the connection.
    pub app: Option<&'a str>,
    /// Whether decoding identified a reset, network error, DNS error, or truncation.
    pub problem: bool,
}
/// A grammar error at a zero-based UTF-8 byte offset in the original input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterError {
    /// Zero-based byte position; input.len() identifies a missing final token.
    pub position: usize,
    /// Plain-English description of what the parser expected.
    pub message: String,
}
/// A parsed display predicate; Default and an empty input match every row.
#[derive(Clone, Debug, Default)]
pub struct Filter(Option<Expr>);
#[derive(Clone, Debug)]
enum Expr {
    Protocol(String),
    Port(u16),
    Host(String),
    App(String),
    Search(String),
    Problem,
    Conversation {
        src: Addr,
        dst: Addr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        ip_proto: Option<u8>,
    },
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}
impl Filter {
    /// Tests a summary row, including protocols carried over TCP or UDP.
    pub fn matches(&self, row: &Row<'_>) -> bool {
        self.0.as_ref().is_none_or(|e| e.matches(row))
    }
    /// Returns true only for a predicate that came from empty input or Default.
    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }
    /// Builds an exact, bidirectional endpoint predicate.
    /// Returns None when either address is absent; missing ports stay absent.
    pub fn conversation(summary: &Summary) -> Option<Self> {
        Some(Self(Some(Expr::Conversation {
            src: summary.src.clone()?,
            dst: summary.dst.clone()?,
            src_port: summary.src_port,
            dst_port: summary.dst_port,
            ip_proto: summary.ip_proto,
        })))
    }
}
fn contains(value: &str, needle: &str) -> bool {
    value.to_lowercase().contains(needle)
}
impl Expr {
    fn matches(&self, row: &Row<'_>) -> bool {
        let s = row.summary;
        match self {
            Self::Protocol(p) => match p.as_str() {
                "tcp" => s.ip_proto == Some(6) || s.tcp.is_some(),
                "udp" => s.ip_proto == Some(17),
                "icmp" => matches!(s.proto, Proto::Icmp | Proto::Icmpv6),
                // ARP carries protocol addresses in a link-layer message (RFC
                // 826, Packet format). An IPv4 address alone does not make it IP.
                "ip" => {
                    s.ip_proto.is_some()
                        || matches!(s.proto, Proto::Ipv4 | Proto::Ipv6)
                        || matches!(s.ether_type, Some(0x0800 | 0x86dd))
                }
                "ipv6" => {
                    s.proto == Proto::Ipv6
                        || s.ether_type == Some(0x86dd)
                        || (s.ip_proto.is_some() && matches!(s.src, Some(Addr::V6(_))))
                }
                _ => s.proto.name().eq_ignore_ascii_case(p),
            },
            Self::Port(p) => s.src_port == Some(*p) || s.dst_port == Some(*p),
            Self::Host(v) => {
                s.src
                    .as_ref()
                    .is_some_and(|a| contains(&text::address(a), v))
                    || s.dst
                        .as_ref()
                        .is_some_and(|a| contains(&text::address(a), v))
                    || row.src_name.is_some_and(|n| contains(n, v))
                    || row.dst_name.is_some_and(|n| contains(n, v))
            }
            Self::App(v) => row.app.is_some_and(|a| contains(a, v)),
            Self::Search(v) => contains(row.sentence, v),
            Self::Problem => row.problem,
            Self::Conversation {
                src,
                dst,
                src_port,
                dst_port,
                ip_proto,
            } => {
                s.ip_proto == *ip_proto
                    && ((s.src.as_ref() == Some(src)
                        && s.dst.as_ref() == Some(dst)
                        && s.src_port == *src_port
                        && s.dst_port == *dst_port)
                        || (s.src.as_ref() == Some(dst)
                            && s.dst.as_ref() == Some(src)
                            && s.src_port == *dst_port
                            && s.dst_port == *src_port))
            }
            Self::Not(e) => !e.matches(row),
            Self::And(a, b) => a.matches(row) && b.matches(row),
            Self::Or(a, b) => a.matches(row) || b.matches(row),
        }
    }
}
#[derive(Debug)]
struct Token {
    value: String,
    position: usize,
    quoted: bool,
}
struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
    end: usize,
}
fn error(position: usize, message: &str) -> FilterError {
    FilterError {
        position,
        message: message.into(),
    }
}
/// Error positions are zero-based byte offsets in the original filter.
/// Accepts at most 4,096 bytes, 256 tokens, and 64 nested terms; empty input matches all.
pub fn parse(input: &str) -> Result<Filter, FilterError> {
    // These limits cap both matching work and recursive parser/AST stack depth.
    if input.len() > 4096 {
        return Err(error(4096, ui::FILTER_TOO_LONG));
    }
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((position, ch)) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }
        let quoted = ch == '"' || ch == '\'';
        let mut value = String::new();
        if quoted {
            let mut closed = false;
            while let Some((_, c)) = chars.next() {
                if c == ch {
                    closed = true;
                    break;
                }
                if c == '\\' {
                    if let Some((_, escaped)) = chars.next() {
                        value.push(escaped);
                    }
                } else {
                    value.push(c);
                }
            }
            if !closed {
                return Err(error(position, ui::FILTER_QUOTE));
            }
        } else if matches!(ch, '(' | ')' | '[' | ']') {
            value.push(if ch == '[' {
                '('
            } else if ch == ']' {
                ')'
            } else {
                ch
            });
        } else {
            value.push(ch);
            while let Some(&(_, c)) = chars.peek() {
                if c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']' | '"' | '\'') {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }
        tokens.push(Token {
            value: value.to_lowercase(),
            position,
            quoted,
        });
        if tokens.len() > 256 {
            return Err(error(position, ui::FILTER_TOO_COMPLEX));
        }
    }
    let mut parser = Parser {
        tokens,
        cursor: 0,
        end: input.len(),
    };
    if parser.tokens.is_empty() {
        return Ok(Filter(None));
    }
    let expr = parser.or(0)?;
    if parser.peek().is_some() {
        return Err(parser.err(ui::FILTER_OPERATOR));
    }
    Ok(Filter(Some(expr)))
}
impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }
    fn is(&self, v: &str) -> bool {
        self.peek().is_some_and(|t| !t.quoted && t.value == v)
    }
    fn err(&self, message: &str) -> FilterError {
        error(self.peek().map_or(self.end, |t| t.position), message)
    }
    fn or(&mut self, depth: usize) -> Result<Expr, FilterError> {
        // Reading tight-binding terms first gives not > and > or precedence.
        let mut a = self.and(depth)?;
        while self.is("or") {
            self.cursor += 1;
            a = Expr::Or(Box::new(a), Box::new(self.and(depth)?));
        }
        Ok(a)
    }
    fn and(&mut self, depth: usize) -> Result<Expr, FilterError> {
        let mut a = self.term(depth)?;
        while self.peek().is_some() && !self.is(")") && !self.is("or") {
            if self.is("and") {
                self.cursor += 1;
            }
            a = Expr::And(Box::new(a), Box::new(self.term(depth)?));
        }
        Ok(a)
    }
    fn term(&mut self, depth: usize) -> Result<Expr, FilterError> {
        if depth >= 64 {
            return Err(self.err(ui::FILTER_TOO_COMPLEX));
        }
        if self.is("not") {
            self.cursor += 1;
            return Ok(Expr::Not(Box::new(self.term(depth + 1)?)));
        }
        if self.is("(") {
            self.cursor += 1;
            let a = self.or(depth + 1)?;
            if !self.is(")") {
                return Err(self.err(ui::FILTER_CLOSE));
            }
            self.cursor += 1;
            return Ok(a);
        }
        if self.peek().is_none() || self.is(")") || self.is("and") || self.is("or") {
            return Err(self.err(ui::FILTER_TERM));
        }
        let token = &self.tokens[self.cursor];
        let word = token.value.clone();
        let quoted = token.quoted;
        self.cursor += 1;
        if !quoted && matches!(word.as_str(), "port" | "host" | "app") {
            if self.peek().is_none()
                || self.is(")")
                || self.is("(")
                || self.is("and")
                || self.is("or")
                || self.is("not")
            {
                return Err(self.err(ui::FILTER_VALUE));
            }
            let t = &self.tokens[self.cursor];
            let result = match word.as_str() {
                "port" => Expr::Port(
                    t.value
                        .parse::<u16>()
                        .map_err(|_| error(t.position, ui::FILTER_PORT))?,
                ),
                "host" => Expr::Host(t.value.clone()),
                _ => Expr::App(t.value.clone()),
            };
            if t.value.is_empty() {
                return Err(error(t.position, ui::FILTER_VALUE));
            }
            self.cursor += 1;
            return Ok(result);
        }
        Ok(if !quoted && word == "problem" {
            Expr::Problem
        } else if !quoted
            && matches!(
                word.as_str(),
                "tcp"
                    | "udp"
                    | "icmp"
                    | "arp"
                    | "dns"
                    | "mdns"
                    | "dhcp"
                    | "http"
                    | "tls"
                    | "quic"
                    | "ip"
                    | "ipv6"
            )
        {
            Expr::Protocol(word)
        } else {
            Expr::Search(word)
        })
    }
}
