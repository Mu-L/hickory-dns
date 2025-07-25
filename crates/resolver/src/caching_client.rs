// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Caching related functionality for the Resolver.

use std::{
    borrow::Cow,
    time::{Duration, Instant},
};

use futures_util::future::BoxFuture;
use once_cell::sync::Lazy;

use crate::{
    cache::{MAX_TTL, ResponseCache, TtlConfig},
    lookup::Lookup,
    proto::{
        NoRecords, ProtoError, ProtoErrorKind,
        op::{Message, OpCode, Query, ResponseCode},
        rr::{
            DNSClass, Name, RData, Record, RecordType,
            domain::usage::{
                DEFAULT, IN_ADDR_ARPA_127, INVALID, IP6_ARPA_1, LOCAL,
                LOCALHOST as LOCALHOST_usage, ONION, ResolverUsage,
            },
            rdata::{A, AAAA, CNAME, PTR},
            resource::RecordRef,
        },
        xfer::{DnsHandle, DnsRequestOptions, DnsResponse, FirstAnswer},
    },
};

static LOCALHOST: Lazy<RData> =
    Lazy::new(|| RData::PTR(PTR(Name::from_ascii("localhost.").unwrap())));
static LOCALHOST_V4: Lazy<RData> = Lazy::new(|| RData::A(A::new(127, 0, 0, 1)));
static LOCALHOST_V6: Lazy<RData> = Lazy::new(|| RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)));

/// Counts the depth of CNAME query resolutions.
#[derive(Default, Clone, Copy)]
struct DepthTracker {
    query_depth: u8,
}

impl DepthTracker {
    fn nest(self) -> Self {
        Self {
            query_depth: self.query_depth + 1,
        }
    }

    fn is_exhausted(self) -> bool {
        self.query_depth + 1 >= Self::MAX_QUERY_DEPTH
    }

    const MAX_QUERY_DEPTH: u8 = 8; // arbitrarily chosen number...
}

// TODO: need to consider this storage type as it compares to Authority in server...
//       should it just be an variation on Authority?
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct CachingClient<C>
where
    C: DnsHandle,
{
    cache: ResponseCache,
    client: C,
    preserve_intermediates: bool,
}

impl<C> CachingClient<C>
where
    C: DnsHandle + Send + 'static,
{
    #[doc(hidden)]
    pub fn new(max_size: u64, client: C, preserve_intermediates: bool) -> Self {
        Self::with_cache(
            ResponseCache::new(max_size, TtlConfig::default()),
            client,
            preserve_intermediates,
        )
    }

    pub(crate) fn with_cache(
        cache: ResponseCache,
        client: C,
        preserve_intermediates: bool,
    ) -> Self {
        Self {
            cache,
            client,
            preserve_intermediates,
        }
    }

    /// Perform a lookup against this caching client, looking first in the cache for a result
    pub fn lookup(
        &self,
        query: Query,
        options: DnsRequestOptions,
    ) -> BoxFuture<'static, Result<Lookup, ProtoError>> {
        Box::pin(Self::inner_lookup(
            query,
            options,
            self.clone(),
            vec![],
            DepthTracker::default(),
        ))
    }

    async fn inner_lookup(
        query: Query,
        options: DnsRequestOptions,
        mut client: Self,
        preserved_records: Vec<Record>,
        depth: DepthTracker,
    ) -> Result<Lookup, ProtoError> {
        // see https://tools.ietf.org/html/rfc6761
        //
        // ```text
        // Name resolution APIs and libraries SHOULD recognize localhost
        // names as special and SHOULD always return the IP loopback address
        // for address queries and negative responses for all other query
        // types.  Name resolution APIs SHOULD NOT send queries for
        // localhost names to their configured caching DNS server(s).
        // ```
        // special use rules only apply to the IN Class
        if query.query_class() == DNSClass::IN {
            let usage = match query.name() {
                n if LOCALHOST_usage.zone_of(n) => &*LOCALHOST_usage,
                n if IN_ADDR_ARPA_127.zone_of(n) => &*LOCALHOST_usage,
                n if IP6_ARPA_1.zone_of(n) => &*LOCALHOST_usage,
                n if INVALID.zone_of(n) => &*INVALID,
                n if LOCAL.zone_of(n) => &*LOCAL,
                n if ONION.zone_of(n) => &*ONION,
                _ => &*DEFAULT,
            };

            match usage.resolver() {
                ResolverUsage::Loopback => match query.query_type() {
                    // TODO: look in hosts for these ips/names first...
                    RecordType::A => return Ok(Lookup::from_rdata(query, LOCALHOST_V4.clone())),
                    RecordType::AAAA => return Ok(Lookup::from_rdata(query, LOCALHOST_V6.clone())),
                    RecordType::PTR => return Ok(Lookup::from_rdata(query, LOCALHOST.clone())),
                    // Are there any other types we can use?
                    _ => return Err(NoRecords::new(query, ResponseCode::NoError).into()),
                },
                // TODO: this requires additional config, as Kubernetes and other systems misuse the .local. zone.
                // when mdns is not enabled we will return errors on LinkLocal ("*.local.") names
                ResolverUsage::LinkLocal => (),
                ResolverUsage::NxDomain => {
                    return Err(NoRecords::new(query, ResponseCode::NXDomain).into());
                }
                ResolverUsage::Normal => (),
            }
        }

        let is_dnssec = client.client.is_verifying_dnssec();

        if let Some(cached_lookup) = client.lookup_from_cache(&query) {
            return cached_lookup;
        };

        let response_message = client
            .client
            .lookup(query.clone(), options)
            .first_answer()
            .await;

        // TODO: technically this might be duplicating work, as name_server already performs this evaluation.
        //  we may want to create a new type, if evaluated... but this is most generic to support any impl in LookupState...
        let response_message = if let Ok(response) = response_message {
            ProtoError::from_response(response)
        } else {
            response_message
        };

        // TODO: take all records and cache them?
        //  if it's DNSSEC they must be signed, otherwise?
        let records: Result<Records, ProtoError> = match response_message {
            // this is the only cacheable form
            Err(e) => match e.kind() {
                ProtoErrorKind::NoRecordsFound(no_records) => {
                    let mut new = no_records.clone();
                    if is_dnssec {
                        new.negative_ttl = None;
                    }
                    Err(new.into())
                }
                _ => return Err(e),
            },
            Ok(response_message) => {
                // allow the handle_noerror function to deal with any error codes
                let records = Self::handle_noerror(
                    &mut client,
                    options,
                    &query,
                    response_message,
                    preserved_records,
                    depth,
                )?;

                Ok(records)
            }
        };

        // after the request, evaluate if we have additional queries to perform
        match records {
            Ok(Records::CnameChain { next: future }) => match future.await {
                Ok(lookup) => client.cname(lookup, query),
                Err(e) => client.cache(query, Err(e)),
            },
            Ok(Records::Exists(rdata)) => client.cache(query, Ok(rdata)),
            Err(e) => client.cache(query, Err(e)),
        }
    }

    /// Check if this query is already cached
    fn lookup_from_cache(&self, query: &Query) -> Option<Result<Lookup, ProtoError>> {
        let now = Instant::now();
        let message_res = self.cache.get(query, now)?;
        let message = match message_res {
            Ok(message) => message,
            Err(err) => return Some(Err(err)),
        };
        Some(Ok(records_to_lookup(query.clone(), message.answers(), now)))
    }

    /// Handle the case where there is no error returned
    fn handle_noerror(
        client: &mut Self,
        options: DnsRequestOptions,
        query: &Query,
        response: DnsResponse,
        mut preserved_records: Vec<Record>,
        depth: DepthTracker,
    ) -> Result<Records, ProtoError> {
        // initial ttl is what CNAMES for min usage
        const INITIAL_TTL: u32 = MAX_TTL;

        // need to capture these before the subsequent and destructive record processing
        let soa = response.soa().as_ref().map(RecordRef::to_owned);
        let negative_ttl = response.negative_ttl();
        let response_code = response.response_code();

        // seek out CNAMES, this is only performed if the query is not a CNAME, ANY, or SRV
        // FIXME: for SRV this evaluation is inadequate. CNAME is a single chain to a single record
        //   for SRV, there could be many different targets. The search_name needs to be enhanced to
        //   be a list of names found for SRV records.
        let (search_name, was_cname, preserved_records) = {
            // this will only search for CNAMEs if the request was not meant to be for one of the triggers for recursion
            let (search_name, cname_ttl, was_cname) =
                if query.query_type().is_any() || query.query_type().is_cname() {
                    (Cow::Borrowed(query.name()), INITIAL_TTL, false)
                } else {
                    // Folds any cnames from the answers section, into the final cname in the answers section
                    //   this works by folding the last CNAME found into the final folded result.
                    //   it assumes that the CNAMEs are in chained order in the DnsResponse Message...
                    // For SRV, the name added for the search becomes the target name.
                    //
                    // TODO: should this include the additionals?
                    response.answers().iter().fold(
                        (Cow::Borrowed(query.name()), INITIAL_TTL, false),
                        |(search_name, cname_ttl, was_cname), r| {
                            match r.data() {
                                RData::CNAME(CNAME(cname)) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl());
                                    debug_assert_eq!(r.record_type(), RecordType::CNAME);
                                    if search_name.as_ref() == r.name() {
                                        return (Cow::Owned(cname.clone()), ttl, true);
                                    }
                                }
                                RData::SRV(srv) => {
                                    // take the minimum TTL of the cname_ttl and the next record in the chain
                                    let ttl = cname_ttl.min(r.ttl());
                                    debug_assert_eq!(r.record_type(), RecordType::SRV);

                                    // the search name becomes the srv.target
                                    return (Cow::Owned(srv.target().clone()), ttl, true);
                                }
                                _ => (),
                            }

                            (search_name, cname_ttl, was_cname)
                        },
                    )
                };

            // take all answers. // TODO: following CNAMES?
            let mut response = response.into_message();
            let answers = response.take_answers();
            let additionals = response.take_additionals();
            let authorities = response.take_authorities();

            // set of names that still require resolution
            // TODO: this needs to be enhanced for SRV
            let mut found_name = false;

            // After following all the CNAMES to the last one, try and lookup the final name
            let records = answers
                .into_iter()
                // Chained records will generally exist in the additionals section
                .chain(additionals)
                .chain(authorities)
                .filter_map(|mut r| {
                    // because this resolved potentially recursively, we want the min TTL from the chain
                    let ttl = cname_ttl.min(r.ttl());
                    r.set_ttl(ttl);
                    // TODO: disable name validation with ResolverOpts? glibc feature...
                    // restrict to the RData type requested
                    if query.query_class() == r.dns_class() {
                        // standard evaluation, it's an any type or it's the requested type and the search_name matches
                        #[allow(clippy::suspicious_operation_groupings)]
                        if (query.query_type().is_any() || query.query_type() == r.record_type())
                            && (search_name.as_ref() == r.name() || query.name() == r.name())
                        {
                            found_name = true;
                            return Some(r);
                        }
                        // CNAME evaluation, the record is from the CNAME lookup chain.
                        if client.preserve_intermediates && r.record_type() == RecordType::CNAME {
                            return Some(r);
                        }
                        // srv evaluation, it's an srv lookup and the srv_search_name/target matches this name
                        //    and it's an IP
                        if query.query_type().is_srv()
                            && r.record_type().is_ip_addr()
                            && search_name.as_ref() == r.name()
                        {
                            found_name = true;
                            Some(r)
                        } else if query.query_type().is_ns() && r.record_type().is_ip_addr() {
                            Some(r)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            // adding the newly collected records to the preserved records
            preserved_records.extend(records);
            if !preserved_records.is_empty() && found_name {
                return Ok(Records::Exists(preserved_records));
            }

            (search_name.into_owned(), was_cname, preserved_records)
        };

        // TODO: for SRV records we *could* do an implicit lookup, but, this requires knowing the type of IP desired
        //    for now, we'll make the API require the user to perform a follow up to the lookups.
        // It was a CNAME, but not included in the request...
        if was_cname && !depth.is_exhausted() {
            let next_query = Query::query(search_name, query.query_type());
            Ok(Records::CnameChain {
                next: Box::pin(Self::inner_lookup(
                    next_query,
                    options,
                    client.clone(),
                    preserved_records,
                    depth.nest(),
                )),
            })
        } else {
            // TODO: review See https://tools.ietf.org/html/rfc2308 for NoData section
            // Note on DNSSEC, in secure_client_handle, if verify_nsec fails then the request fails.
            //   this will mean that no unverified negative caches will make it to this point and be stored
            let mut new = NoRecords::new(query.clone(), response_code);
            new.soa = soa.map(Box::new);
            new.negative_ttl = negative_ttl;
            Err(new.into())
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn cname(&self, lookup: Lookup, query: Query) -> Result<Lookup, ProtoError> {
        let mut message = Message::response(0, OpCode::Query);
        message.add_answers(lookup.records().iter().cloned());
        self.cache.insert(query, Ok(message), Instant::now());
        Ok(lookup)
    }

    fn cache(
        &self,
        query: Query,
        records: Result<Vec<Record>, ProtoError>,
    ) -> Result<Lookup, ProtoError> {
        let rdata = match records {
            Ok(rdata) => rdata,
            Err(err) => {
                self.cache.insert(query, Err(err.clone()), Instant::now());
                return Err(err);
            }
        };

        let now = Instant::now();
        let lookup = records_to_lookup(query.clone(), &rdata, now);

        let mut message = Message::response(0, OpCode::Query);
        message.add_answers(rdata);
        self.cache.insert(query, Ok(message), now);

        Ok(lookup)
    }

    /// Flushes/Removes all entries from the cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

enum Records {
    /// The records exists, a vec of rdata with ttl
    Exists(Vec<Record>),
    /// Future lookup for recursive cname records
    CnameChain {
        next: BoxFuture<'static, Result<Lookup, ProtoError>>,
    },
}

/// Helper function to construct a [`Lookup`] from a list of records.
fn records_to_lookup(query: Query, records: &[Record], now: Instant) -> Lookup {
    let ttl = records.iter().map(Record::ttl).min().unwrap_or(MAX_TTL);
    let valid_until = now + Duration::from_secs(ttl.into());
    let records = records.to_vec().into();
    Lookup::new_with_deadline(query, records, valid_until)
}

// see also the lookup_tests.rs in integration-tests crate
#[cfg(test)]
mod tests {
    use std::net::*;
    use std::str::FromStr;
    use std::time::*;

    use crate::proto::op::{Message, Query};
    use crate::proto::rr::rdata::{NS, SRV};
    use crate::proto::rr::{Name, Record};
    use futures_executor::block_on;
    use test_support::subscribe;

    use super::*;
    use crate::cache::TtlConfig;
    use crate::lookup_ip::tests::*;

    #[test]
    fn test_empty_cache() {
        subscribe();
        let cache = ResponseCache::new(1, TtlConfig::default());
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        if let ProtoErrorKind::NoRecordsFound(NoRecords {
            query,
            negative_ttl,
            ..
        }) = block_on(CachingClient::inner_lookup(
            Query::new(),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .unwrap_err()
        .kind()
        {
            assert_eq!(*query, Box::new(Query::new()));
            assert_eq!(*negative_ttl, None);
        } else {
            panic!("wrong error received")
        }
    }

    #[test]
    fn test_from_cache() {
        subscribe();
        let cache = ResponseCache::new(1, TtlConfig::default());
        let query = Query::new();
        let mut message = Message::response(0, OpCode::Query);
        message.add_answer(Record::from_rdata(
            query.name().clone(),
            u32::MAX,
            RData::A(A::new(127, 0, 0, 1)),
        ));
        cache.insert(query.clone(), Ok(message), Instant::now());

        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::new(),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(A::new(127, 0, 0, 1))]
        );
    }

    #[test]
    fn test_no_cache_insert() {
        subscribe();
        let cache = ResponseCache::new(1, TtlConfig::default());
        // first should come from client...
        let client = mock(vec![v4_message()]);
        let client = CachingClient::with_cache(cache.clone(), client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::root(), RecordType::A),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(A::new(127, 0, 0, 1))]
        );

        // next should come from cache...
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::root(), RecordType::A),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .unwrap();

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::A(A::new(127, 0, 0, 1))]
        );
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn cname_message() -> Result<DnsResponse, ProtoError> {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::A,
        ));
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap())),
        )]);
        Ok(DnsResponse::from_message(message).unwrap())
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn srv_message() -> Result<DnsResponse, ProtoError> {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_str("_443._tcp.www.example.com.").unwrap(),
            RecordType::SRV,
        ));
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("_443._tcp.www.example.com.").unwrap(),
            86400,
            RData::SRV(SRV::new(
                1,
                2,
                443,
                Name::from_str("www.example.com.").unwrap(),
            )),
        )]);
        Ok(DnsResponse::from_message(message).unwrap())
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn ns_message() -> Result<DnsResponse, ProtoError> {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::NS,
        ));
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::NS(NS(Name::from_str("www.example.com.").unwrap())),
        )]);
        Ok(DnsResponse::from_message(message).unwrap())
    }

    fn no_recursion_on_query_test(query_type: RecordType) {
        let cache = ResponseCache::new(1, TtlConfig::default());

        // the cname should succeed, we shouldn't query again after that, which would cause an error...
        let client = mock(vec![error(), cname_message()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), query_type),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::CNAME(CNAME(
                Name::from_str("actual.example.com.").unwrap()
            ))]
        );
    }

    #[test]
    fn test_no_recursion_on_cname_query() {
        subscribe();
        no_recursion_on_query_test(RecordType::CNAME);
    }

    #[test]
    fn test_no_recursion_on_all_query() {
        subscribe();
        no_recursion_on_query_test(RecordType::ANY);
    }

    #[test]
    fn test_non_recursive_srv_query() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        // the cname should succeed, we shouldn't query again after that, which would cause an error...
        let client = mock(vec![error(), srv_message()]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![RData::SRV(SRV::new(
                1,
                2,
                443,
                Name::from_str("www.example.com.").unwrap(),
            ))]
        );
    }

    #[test]
    fn test_single_srv_query_response() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        let mut message = srv_message().unwrap().into_message();
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap())),
        ));
        message.insert_additionals(vec![
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ),
        ]);

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(
                Name::from_str("_443._tcp.www.example.com.").unwrap(),
                RecordType::SRV,
            ),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![
                RData::SRV(SRV::new(
                    1,
                    2,
                    443,
                    Name::from_str("www.example.com.").unwrap(),
                )),
                RData::A(A::new(127, 0, 0, 1)),
                RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]
        );
    }

    // TODO: if we ever enable recursive lookups for SRV, here are the tests...
    // #[test]
    // fn test_recursive_srv_query() {
    //     let cache = Arc::new(Mutex::new(DnsLru::new(1)));

    //     let mut message = Message::new();
    //     message.add_answer(Record::from_rdata(
    //         Name::from_str("www.example.com.").unwrap(),
    //         86400,
    //         RecordType::CNAME,
    //         RData::CNAME(Name::from_str("actual.example.com.").unwrap()),
    //     ));
    //     message.insert_additionals(vec![
    //         Record::from_rdata(
    //             Name::from_str("actual.example.com.").unwrap(),
    //             86400,
    //             RecordType::A,
    //             RData::A(Ipv4Addr::LOCALHOST),
    //         ),
    //     ]);

    //     let mut client = mock(vec![error(), Ok(DnsResponse::from_message(message).unwrap()), srv_message()]);

    //     let ips = QueryState::lookup(
    //         Query::query(
    //             Name::from_str("_443._tcp.www.example.com.").unwrap(),
    //             RecordType::SRV,
    //         ),
    //         Default::default(),
    //         &mut client,
    //         cache.clone(),
    //     ).wait()
    //         .expect("lookup failed");

    //     assert_eq!(
    //         ips.iter().cloned().collect::<Vec<_>>(),
    //         vec![
    //             RData::SRV(SRV::new(
    //                 1,
    //                 2,
    //                 443,
    //                 Name::from_str("www.example.com.").unwrap(),
    //             )),
    //             RData::A(Ipv4Addr::LOCALHOST),
    //             //RData::AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
    //         ]
    //     );
    // }

    #[test]
    fn test_single_ns_query_response() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        let mut message = ns_message().unwrap().into_message();
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.com.").unwrap(),
            86400,
            RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap())),
        ));
        message.insert_additionals(vec![
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::A(A::new(127, 0, 0, 1)),
            ),
            Record::from_rdata(
                Name::from_str("actual.example.com.").unwrap(),
                86400,
                RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ),
        ]);

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, false);

        let ips = block_on(CachingClient::inner_lookup(
            Query::query(Name::from_str("www.example.com.").unwrap(), RecordType::NS),
            DnsRequestOptions::default(),
            client,
            vec![],
            DepthTracker::default(),
        ))
        .expect("lookup failed");

        assert_eq!(
            ips.iter().cloned().collect::<Vec<_>>(),
            vec![
                RData::NS(NS(Name::from_str("www.example.com.").unwrap())),
                RData::A(A::new(127, 0, 0, 1)),
                RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ]
        );
    }

    fn cname_ttl_test(first: u32, second: u32) {
        let lru = ResponseCache::new(1, TtlConfig::default());
        // expecting no queries to be performed
        let mut client = CachingClient::with_cache(lru, mock(vec![error()]), false);

        let mut message = Message::query();
        message.insert_answers(vec![Record::from_rdata(
            Name::from_str("ttl.example.com.").unwrap(),
            first,
            RData::CNAME(CNAME(Name::from_str("actual.example.com.").unwrap())),
        )]);
        message.insert_additionals(vec![Record::from_rdata(
            Name::from_str("actual.example.com.").unwrap(),
            second,
            RData::A(A::new(127, 0, 0, 1)),
        )]);

        let records = CachingClient::handle_noerror(
            &mut client,
            DnsRequestOptions::default(),
            &Query::query(Name::from_str("ttl.example.com.").unwrap(), RecordType::A),
            DnsResponse::from_message(message).unwrap(),
            vec![],
            DepthTracker::default(),
        );

        if let Ok(records) = records {
            if let Records::Exists(records) = records {
                for record in records.iter() {
                    if record.record_type() == RecordType::CNAME {
                        continue;
                    }
                    assert_eq!(record.ttl(), 1);
                }
            } else {
                panic!("records don't exist");
            }
        } else {
            panic!("error getting records");
        }
    }

    #[test]
    fn test_cname_ttl() {
        subscribe();
        cname_ttl_test(1, 2);
        cname_ttl_test(2, 1);
    }

    #[test]
    fn test_early_return_localhost() {
        subscribe();
        let cache = ResponseCache::new(0, TtlConfig::default());
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::A);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST_V4.clone()]
            );
        }

        {
            let query = Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::AAAA);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST_V6.clone()]
            );
        }

        {
            let query = Query::query(Name::from(Ipv4Addr::LOCALHOST), RecordType::PTR);
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST.clone()]
            );
        }

        {
            let query = Query::query(
                Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                RecordType::PTR,
            );
            let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default()))
                .expect("should have returned localhost");
            assert_eq!(lookup.query(), &query);
            assert_eq!(
                lookup.iter().cloned().collect::<Vec<_>>(),
                vec![LOCALHOST.clone()]
            );
        }

        assert!(
            block_on(client.lookup(
                Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::MX),
                DnsRequestOptions::default()
            ))
            .is_err()
        );

        assert!(
            block_on(client.lookup(
                Query::query(Name::from(Ipv4Addr::LOCALHOST), RecordType::MX),
                DnsRequestOptions::default()
            ))
            .is_err()
        );

        assert!(
            block_on(client.lookup(
                Query::query(
                    Name::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    RecordType::MX
                ),
                DnsRequestOptions::default()
            ))
            .is_err()
        );
    }

    #[test]
    fn test_early_return_invalid() {
        subscribe();
        let cache = ResponseCache::new(0, TtlConfig::default());
        let client = mock(vec![empty()]);
        let client = CachingClient::with_cache(cache, client, false);

        assert!(
            block_on(client.lookup(
                Query::query(
                    Name::from_ascii("horrible.invalid.").unwrap(),
                    RecordType::A,
                ),
                DnsRequestOptions::default()
            ))
            .is_err()
        );
    }

    #[test]
    fn test_no_error_on_dot_local_no_mdns() {
        subscribe();

        let cache = ResponseCache::new(1, TtlConfig::default());

        let mut message = srv_message().unwrap().into_message();
        message.add_query(Query::query(
            Name::from_ascii("www.example.local.").unwrap(),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_str("www.example.local.").unwrap(),
            86400,
            RData::A(A::new(127, 0, 0, 1)),
        ));

        let client = mock(vec![
            error(),
            Ok(DnsResponse::from_message(message).unwrap()),
        ]);
        let client = CachingClient::with_cache(cache, client, false);

        assert!(
            block_on(client.lookup(
                Query::query(
                    Name::from_ascii("www.example.local.").unwrap(),
                    RecordType::A,
                ),
                DnsRequestOptions::default()
            ))
            .is_ok()
        );
    }
}
