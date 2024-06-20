use crate::rr::dnssec::rdata::dnskey::DNSKEY;
use crate::rr::dnssec::Algorithm;
use crate::serialize::txt::{ParseError, ParseErrorKind, ParseResult};

fn bit_is_set(value: u16, bit: usize) -> bool {
    let mask = 1 << bit;
    value & mask == mask
}

#[allow(deprecated)]
pub(crate) fn parse<'i, I: Iterator<Item = &'i str>>(mut tokens: I) -> ParseResult<DNSKEY> {
    let flags_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("flags not present")))?;
    let protocol_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("protocol not present")))?;
    let algorithm_str: &str = tokens
        .next()
        .ok_or_else(|| ParseError::from(ParseErrorKind::Message("algorithm not present")))?;

    let flags: u16 = flags_str.parse()?;
    if ![0, 256, 257].contains(&flags) {
        return Err(ParseError::from(ParseErrorKind::Message(
            "flags field must be one of: 0, 256, 257",
        )));
    }

    let secure_entry_point = bit_is_set(flags, 0);
    let revoke = bit_is_set(flags, 7);
    let zone_key = bit_is_set(flags, 8);

    let protocol: u8 = protocol_str.parse()?;

    if protocol != 3 {
        return Err(ParseError::from(ParseErrorKind::Message(
            "protocol field must be 3",
        )));
    }

    let algorithm = Algorithm::from_u8(algorithm_str.parse()?);

    let public_key_str: String = tokens.collect();
    if public_key_str.is_empty() {
        return Err(ParseError::from(ParseErrorKind::Message(
            "public key not present",
        )));
    }

    let public_key = data_encoding::BASE64.decode(public_key_str.as_bytes())?;

    Ok(DNSKEY::new(
        zone_key,
        secure_entry_point,
        revoke,
        algorithm,
        public_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_parsing() {
        assert_eq!(
            parse(
                "256 3 7 \
                 AwEAAdr2WcwRKS6h0NOnuL6Hp+2aW8YXnlaIw/zA0KI5s3MLS8TFM35s \
                 s99M2rPI+gMXySFlWSMxfAUOCnqf/+IOyUsp1TaSzcYnFqUzkXHTRxWN \
                 nMclFnY5lQ38PNjZPJ+xEArJRUShBeWpsps8kqoH/ClPrNGdDYdiKCML \
                 HreuayQZ"
                    .split(' ')
            )
            .unwrap(),
            DNSKEY::new(
                true,
                false,
                false,
                Algorithm::RSASHA1NSEC3SHA1,
                vec![
                    3, 1, 0, 1, 218, 246, 89, 204, 17, 41, 46, 161, 208, 211, 167, 184, 190, 135,
                    167, 237, 154, 91, 198, 23, 158, 86, 136, 195, 252, 192, 208, 162, 57, 179,
                    115, 11, 75, 196, 197, 51, 126, 108, 179, 223, 76, 218, 179, 200, 250, 3, 23,
                    201, 33, 101, 89, 35, 49, 124, 5, 14, 10, 122, 159, 255, 226, 14, 201, 75, 41,
                    213, 54, 146, 205, 198, 39, 22, 165, 51, 145, 113, 211, 71, 21, 141, 156, 199,
                    37, 22, 118, 57, 149, 13, 252, 60, 216, 217, 60, 159, 177, 16, 10, 201, 69, 68,
                    161, 5, 229, 169, 178, 155, 60, 146, 170, 7, 252, 41, 79, 172, 209, 157, 13,
                    135, 98, 40, 35, 11, 30, 183, 174, 107, 36, 25
                ]
            )
        );
    }
}
