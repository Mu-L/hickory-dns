#[cfg(feature = "dnssec")]
use crate::proto::rr::dnssec::TrustAnchor;

/// `Recursor`'s DNSSEC policy
// `Copy` can only be implemented when `dnssec` is disabled we don't want to remove a trait
// implementation when a feature is enabled as features are meant to be additive
#[allow(missing_copy_implementations)]
#[derive(Clone)]
pub enum DnssecPolicy {
    /// security unaware; DNSSEC records will not be requested nor processed
    SecurityUnaware,

    /// DNSSEC validation is disabled; DNSSEC records will be requested and processed
    #[cfg(feature = "dnssec")]
    ValidationDisabled,

    /// DNSSEC validation is enabled and will use the chosen `trust_anchor` set of keys
    #[cfg(feature = "dnssec")]
    ValidateWithStaticKey {
        /// set to `None` to use built-in trust anchor
        trust_anchor: Option<TrustAnchor>,
    },
    // TODO RFC5011
    // ValidateWithInitialKey { .. },
}

impl DnssecPolicy {
    pub(crate) fn is_security_aware(&self) -> bool {
        !matches!(self, Self::SecurityUnaware)
    }
}
