// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! class of DNS operations, in general always IN for internet
#![allow(clippy::use_self)]

use alloc::string::ToString;
use core::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::serialize::binary::*;

/// The DNS Record class
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[allow(dead_code)]
pub enum DNSClass {
    /// Internet
    IN,
    /// Chaos
    CH,
    /// Hesiod
    HS,
    /// QCLASS NONE
    NONE,
    /// QCLASS * (ANY)
    ANY,
    /// Special class for OPT Version, it was overloaded for EDNS - RFC 6891
    /// From the RFC: `Values lower than 512 MUST be treated as equal to 512`
    OPT(u16),
    /// Unknown DNSClass was parsed
    Unknown(u16),
}

impl FromStr for DNSClass {
    type Err = ProtoError;

    /// Convert from `&str` to `DNSClass`
    ///
    /// ```
    /// use std::str::FromStr;
    /// use hickory_proto::rr::dns_class::DNSClass;
    ///
    /// let var: DNSClass = DNSClass::from_str("IN").unwrap();
    /// assert_eq!(DNSClass::IN, var);
    /// ```
    fn from_str(str: &str) -> ProtoResult<Self> {
        debug_assert!(str.chars().all(|x| !char::is_ascii_lowercase(&x)));
        match str {
            "IN" => Ok(Self::IN),
            "CH" => Ok(Self::CH),
            "HS" => Ok(Self::HS),
            "NONE" => Ok(Self::NONE),
            "ANY" | "*" => Ok(Self::ANY),
            _ => Err(ProtoErrorKind::UnknownDnsClassStr(str.to_string()).into()),
        }
    }
}

impl DNSClass {
    /// Return the OPT version from value
    pub fn for_opt(value: u16) -> Self {
        // From RFC 6891: `Values lower than 512 MUST be treated as equal to 512`
        let value = value.max(512);
        Self::OPT(value)
    }
}

impl BinEncodable for DNSClass {
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        encoder.emit_u16((*self).into())
    }
}

impl BinDecodable<'_> for DNSClass {
    fn read(decoder: &mut BinDecoder<'_>) -> ProtoResult<Self> {
        let this = Self::from(
            decoder.read_u16()?.unverified(/*DNSClass is verified as safe in processing this*/),
        );

        Ok(this)
    }
}

// TODO make these a macro or annotation

/// Convert from `DNSClass` to `&str`
///
/// ```
/// use hickory_proto::rr::dns_class::DNSClass;
///
/// let var: &'static str = DNSClass::IN.into();
/// assert_eq!("IN", var);
/// ```
impl From<DNSClass> for &'static str {
    fn from(rt: DNSClass) -> &'static str {
        match rt {
            DNSClass::IN => "IN",
            DNSClass::CH => "CH",
            DNSClass::HS => "HS",
            DNSClass::NONE => "NONE",
            DNSClass::ANY => "ANY",
            DNSClass::OPT(_) => "OPT",
            DNSClass::Unknown(_) => "UNKNOWN",
        }
    }
}

/// Convert from `u16` to `DNSClass`
///
/// ```
/// use hickory_proto::rr::dns_class::DNSClass;
///
/// let var: DNSClass = 1u16.into();
/// assert_eq!(DNSClass::IN, var);
/// ```
impl From<u16> for DNSClass {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            3 => Self::CH,
            4 => Self::HS,
            254 => Self::NONE,
            255 => Self::ANY,
            _ => Self::Unknown(value),
        }
    }
}

/// Convert from `DNSClass` to `u16`
///
/// ```
/// use hickory_proto::rr::dns_class::DNSClass;
///
/// let var: u16 = DNSClass::IN.into();
/// assert_eq!(1, var);
/// ```
impl From<DNSClass> for u16 {
    fn from(rt: DNSClass) -> Self {
        match rt {
            DNSClass::IN => 1,
            DNSClass::CH => 3,
            DNSClass::HS => 4,
            DNSClass::NONE => 254,
            DNSClass::ANY => 255,
            // see https://tools.ietf.org/html/rfc6891#section-6.1.2
            DNSClass::OPT(max_payload_len) => max_payload_len.max(512),
            DNSClass::Unknown(unknown) => unknown,
        }
    }
}

impl PartialOrd<Self> for DNSClass {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DNSClass {
    fn cmp(&self, other: &Self) -> Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}

impl Display for DNSClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(Into::<&str>::into(*self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_order() {
        let ordered = vec![
            DNSClass::IN,
            DNSClass::CH,
            DNSClass::HS,
            DNSClass::NONE,
            DNSClass::ANY,
        ];
        let mut unordered = vec![
            DNSClass::NONE,
            DNSClass::HS,
            DNSClass::CH,
            DNSClass::IN,
            DNSClass::ANY,
        ];

        unordered.sort();

        assert_eq!(unordered, ordered);
    }

    #[test]
    fn check_dns_class_parse_wont_panic_with_symbols() {
        let dns_class = "a-b-c".to_ascii_uppercase().parse::<DNSClass>();
        assert!(matches!(&dns_class, Err(ProtoError { .. })));
    }
}
