// Copyright 2015-2022 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::proto::h2::{HttpsClientConnect, HttpsClientStream, HttpsClientStreamBuilder};
use crate::proto::runtime::{RuntimeProvider, TokioTime};
use crate::proto::tcp::DnsTcpStream;
use crate::proto::xfer::{DnsExchange, DnsExchangeConnect};
use crate::tls::CLIENT_CONFIG;

#[allow(clippy::type_complexity)]
#[allow(unused)]
pub(crate) fn new_https_stream<P: RuntimeProvider>(
    socket_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
    dns_name: String,
    http_endpoint: String,
    client_config: Option<Arc<rustls::ClientConfig>>,
    provider: P,
) -> DnsExchangeConnect<HttpsClientConnect<P::Tcp>, HttpsClientStream, TokioTime> {
    let client_config = if let Some(client_config) = client_config {
        client_config
    } else {
        match CLIENT_CONFIG.clone() {
            Ok(client_config) => client_config,
            Err(error) => return DnsExchange::error(error),
        }
    };

    let mut https_builder = HttpsClientStreamBuilder::with_client_config(client_config, provider);
    if let Some(bind_addr) = bind_addr {
        https_builder.bind_addr(bind_addr);
    }
    DnsExchange::connect(https_builder.build(socket_addr, dns_name, http_endpoint))
}

#[allow(clippy::type_complexity)]
pub(crate) fn new_https_stream_with_future<S, F>(
    future: F,
    socket_addr: SocketAddr,
    dns_name: String,
    http_endpoint: String,
    client_config: Option<Arc<rustls::ClientConfig>>,
) -> DnsExchangeConnect<HttpsClientConnect<S>, HttpsClientStream, TokioTime>
where
    S: DnsTcpStream + Send + 'static,
    F: Future<Output = std::io::Result<S>> + Send + Unpin + 'static,
{
    let client_config = if let Some(client_config) = client_config {
        client_config
    } else {
        match CLIENT_CONFIG.clone() {
            Ok(client_config) => client_config,
            Err(error) => return DnsExchange::error(error),
        }
    };

    DnsExchange::connect(HttpsClientConnect::new(
        future,
        client_config,
        socket_addr,
        dns_name,
        http_endpoint,
    ))
}

#[cfg(any(feature = "webpki-roots", feature = "native-certs"))]
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use tokio::runtime::Runtime;

    use crate::config::{ResolverConfig, ResolverOpts};
    use crate::name_server::TokioConnectionProvider;
    use crate::TokioResolver;

    fn https_test(config: ResolverConfig) {
        let io_loop = Runtime::new().unwrap();

        let resolver = TokioResolver::new(
            config,
            ResolverOpts {
                try_tcp_on_error: true,
                ..ResolverOpts::default()
            },
            TokioConnectionProvider::default(),
        );

        let response = io_loop
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
                    ))
                );
            }
        }

        // check if there is another connection created
        let response = io_loop
            .block_on(resolver.lookup_ip("www.example.com."))
            .expect("failed to run lookup");

        assert_eq!(response.iter().count(), 1);
        for address in response.iter() {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x21f, 0xcb07, 0x6820, 0x80da, 0xaf6b, 0x8b2c,
                    ))
                );
            }
        }
    }

    #[test]
    fn test_google_https() {
        https_test(ResolverConfig::google_https())
    }

    #[test]
    fn test_cloudflare_https() {
        https_test(ResolverConfig::cloudflare_https())
    }
}
