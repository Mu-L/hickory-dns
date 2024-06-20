// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{
    borrow::Cow,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::error::ConfigError;
use crate::proto::{
    rr::{RData, Record, RecordSet},
    serialize::txt::Parser,
};
use crate::resolver::Name;
#[cfg(feature = "dnssec")]
use crate::{proto::rr::dnssec::TrustAnchor, recursor::DnssecPolicy};

/// Configuration for file based zones
#[derive(Clone, Deserialize, Eq, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecursiveConfig {
    /// File with roots, aka hints
    pub roots: PathBuf,

    /// Maximum nameserver cache size
    #[serde(default = "ns_cache_size_default")]
    pub ns_cache_size: usize,

    /// Maximum DNS record cache size
    #[serde(default = "record_cache_size_default")]
    pub record_cache_size: usize,

    /// DNSSEC policy
    #[cfg(feature = "dnssec")]
    #[serde(default)]
    pub dnssec_policy: DnssecPolicyConfig,
}

impl RecursiveConfig {
    pub(crate) fn read_roots(
        &self,
        root_dir: Option<&Path>,
    ) -> Result<Vec<SocketAddr>, ConfigError> {
        let path = if let Some(root_dir) = root_dir {
            Cow::Owned(root_dir.join(&self.roots))
        } else {
            Cow::Borrowed(&self.roots)
        };

        let mut roots = File::open(path.as_ref())?;
        let mut roots_str = String::new();
        roots.read_to_string(&mut roots_str)?;

        let (_zone, roots_zone) =
            Parser::new(roots_str, Some(path.into_owned()), Some(Name::root())).parse()?;

        // TODO: we may want to deny some of the root nameservers, for reasons...
        Ok(roots_zone
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .map(Record::data)
            .filter_map(RData::ip_addr) // we only want IPs
            .map(|ip| SocketAddr::from((ip, 53))) // all the roots only have tradition DNS ports
            .collect())
    }
}

fn ns_cache_size_default() -> usize {
    1024
}
fn record_cache_size_default() -> usize {
    1048576
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub enum DnssecPolicyConfig {
    /// security unaware; DNSSEC records will not be requested nor processed
    SecurityUnaware,

    /// DNSSEC validation is disabled; DNSSEC records will be requested and processed
    #[cfg(feature = "dnssec")]
    ValidationDisabled,

    /// DNSSEC validation is enabled and will use the chosen `trust_anchor` set of keys
    #[cfg(feature = "dnssec")]
    ValidateWithStaticKey {
        /// set to `None` to use built-in trust anchor
        path: Option<PathBuf>,
    },
}

impl Default for DnssecPolicyConfig {
    fn default() -> Self {
        Self::SecurityUnaware
    }
}

impl DnssecPolicyConfig {
    pub(crate) fn load(&self) -> Result<DnssecPolicy, String> {
        let policy = match self {
            Self::SecurityUnaware => DnssecPolicy::SecurityUnaware,
            #[cfg(feature = "dnssec")]
            Self::ValidationDisabled => DnssecPolicy::ValidationDisabled,
            #[cfg(feature = "dnssec")]
            Self::ValidateWithStaticKey { path } => DnssecPolicy::ValidateWithStaticKey {
                trust_anchor: path
                    .as_ref()
                    .map(|path| load_trust_anchor(path))
                    .transpose()?,
            },
        };

        Ok(policy)
    }
}

#[cfg(feature = "dnssec")]
fn load_trust_anchor(path: &Path) -> Result<TrustAnchor, String> {
    use std::fs;

    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;

    parse_trust_anchor(&contents)
}

#[cfg(feature = "dnssec")]
fn parse_trust_anchor(input: &str) -> Result<TrustAnchor, String> {
    use crate::proto::rr::dnssec::rdata::DNSKEY;
    use crate::proto::rr::dnssec::PublicKeyEnum;
    use crate::proto::rr::{RecordData, RecordType};

    let parser = Parser::new(input, None, Some(Name::root()));
    let (_, records) = parser.parse().map_err(|e| e.to_string())?;

    let mut trust_anchor = TrustAnchor::new();
    for (key, rrset) in records {
        if key.record_type == RecordType::DNSKEY {
            for record in rrset.records_without_rrsigs() {
                if let Some(dnskey) = DNSKEY::try_borrow(record.data()) {
                    // XXX filter based on `dnskey.flags()`?
                    let key =
                        PublicKeyEnum::from_public_bytes(dnskey.public_key(), dnskey.algorithm())
                            .map_err(|e| e.to_string())?;
                    trust_anchor.insert_trust_anchor(&key);
                }
            }
        }
    }

    Ok(trust_anchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "dnssec")]
    #[test]
    fn can_parse_trust_anchor_file() {
        let input = ".  86400   IN  DNSKEY  257 3 7 \
                     AwEAAbTjadQTyqYZ5Jx3QGMosforSBOvujO3z09NX1p96kJUYbsX6zGo \
                     IixI4ZfnsNNRekNMd1CgdQnuk0npUwFH5PQgjvRhlzVKX6SvozipHl18 \
                     mmG4nParXAsnoYQuHvFlHwl1g/wlamG2sUJJFFh2wluqfkOcAFLVWqTJ \
                     EJEg3yokqrMlEnfdcVkE4fq4lrPSVCJwHUKIALJhBaDC4sfk6t1KW6l1 \
                     2VAmUnsVAMBBOQcugu2q4CrasQd6BA2PGcRZRWjgkIpxS68TTMkGh7cV \
                     Ua5YjXbwtUoxwb0A/C5W+hKjzs8AxB5GHD2cJ57XZV/sPYvVDSOMt1Fy \
                     OmhysyD7zn0=
.   86400   IN  DNSKEY  256 3 7 \
AwEAAcmBaOlj+QbJJpzN04oZ78O0IFH63z6Ykfz1xbN9stGQG5pHSgIN \
nIUahUjTwpUgpQn5p2k5+Zc8G41NapLrHV19Nb4HXx19BSKcokbH92xI \
2Cx0ztd+fSFbb0A53uVI9iLmDMGxTV14S1c7UA5ymU2XfxDndlVAfd33 \
nj8oN7Ax";

        let trust_anchor = parse_trust_anchor(input).unwrap();
        assert_eq!(2, trust_anchor.len());
    }

    #[cfg(all(feature = "dnssec", feature = "toml"))]
    #[test]
    fn can_parse_recursive_config() {
        let input = r#"roots = "/etc/root.hints"
dnssec_policy.ValidateWithStaticKey.path = "/etc/trusted-key.toml""#;

        let config: RecursiveConfig = toml::from_str(input).unwrap();

        if let DnssecPolicyConfig::ValidateWithStaticKey { path } = config.dnssec_policy {
            assert_eq!(Some(Path::new("/etc/trusted-key.toml")), path.as_deref());
        } else {
            unreachable!()
        }
    }
}
