// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `DnsHandle` types perform conversions of the raw DNS messages before sending the messages on the specified streams.

use futures_util::stream::Stream;
#[cfg(any(feature = "std", feature = "no-std-rand"))]
use tracing::debug;

use crate::error::*;
use crate::op::Query;
#[cfg(any(feature = "std", feature = "no-std-rand"))]
use crate::op::{Edns, Message};
use crate::xfer::{DnsRequest, DnsRequestOptions, DnsResponse, SerialMessage};

// TODO: this should be configurable
// > An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly all current networks.
// https://dnsflagday.net/2020/
#[cfg(any(feature = "std", feature = "no-std-rand"))]
const MAX_PAYLOAD_LEN: u16 = 1232;

/// Implementations of Sinks for sending DNS messages
pub trait DnsStreamHandle: 'static + Send {
    /// Sends a message to the Handle for delivery to the server.
    fn send(&mut self, buffer: SerialMessage) -> Result<(), ProtoError>;
}

/// A trait for implementing high level functions of DNS.
pub trait DnsHandle: 'static + Clone + Send + Sync + Unpin {
    /// The associated response from the response stream, this should resolve to the Response messages
    type Response: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static;

    /// Only returns true if and only if this DNS handle is validating DNSSEC.
    ///
    /// If the DnsHandle impl is wrapping other clients, then the correct option is to delegate the question to the wrapped client.
    fn is_verifying_dnssec(&self) -> bool {
        false
    }

    /// Allow for disabling EDNS
    fn is_using_edns(&self) -> bool {
        true
    }

    /// Send a message via the channel in the client
    ///
    /// # Arguments
    ///
    /// * `request` - the fully constructed Message to send, note that most implementations of
    ///   will most likely be required to rewrite the QueryId, do no rely on that as
    ///   being stable.
    fn send(&self, request: DnsRequest) -> Self::Response;

    /// A *classic* DNS query
    ///
    /// This is identical to `query`, but instead takes a `Query` object.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to lookup
    /// * `options` - options to use when constructing the message
    #[cfg(any(feature = "std", feature = "no-std-rand"))]
    fn lookup(&self, query: Query, options: DnsRequestOptions) -> Self::Response {
        debug!("querying: {} {:?}", query.name(), query.query_type());
        self.send(build_request(query, options))
    }

    /// A *classic* DNS query
    ///
    /// This is identical to `query`, but instead takes a `Query` object.
    ///
    /// # Arguments
    ///
    /// * `query` - the query to lookup
    /// * `options` - options to use when constructing the message
    #[cfg(not(any(feature = "std", feature = "no-std-rand")))]
    fn lookup(&self, query: Query, options: DnsRequestOptions) -> Self::Response;
}

#[cfg_attr(not(any(feature = "std", feature = "no-std-rand")), expect(unused_mut))]
#[cfg(any(feature = "std", feature = "no-std-rand"))]
fn build_request(mut query: Query, options: DnsRequestOptions) -> DnsRequest {
    // build the message
    let mut message = Message::query();
    let mut original_query = None;

    #[cfg(feature = "std")]
    if options.case_randomization {
        original_query = Some(query.clone());
        query.name.randomize_label_case();
    }

    message
        .add_query(query)
        .set_recursion_desired(options.recursion_desired);

    // Extended dns
    if options.use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0)
            .set_dnssec_ok(options.edns_set_dnssec_ok);
    }

    DnsRequest::new(message, options).with_original_query(original_query)
}
