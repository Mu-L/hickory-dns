use std::{net::Ipv4Addr, time::Duration};

use dns_test::{
    FQDN, Result,
    client::{Client, DigSettings},
    record::RecordType,
    tshark::{Capture, Direction},
    zone_file::SignSettings,
};

use crate::resolver::dnssec::fixtures;

#[test]
fn clears_ad_bit_in_outgoing_queries() -> Result<()> {
    let leaf_ipv4_addr = Ipv4Addr::new(1, 2, 3, 4);
    let leaf_fqdn = FQDN::EXAMPLE_SUBDOMAIN;

    let (resolver, nameservers, _trust_anchor) =
        fixtures::minimally_secure(leaf_fqdn.clone(), leaf_ipv4_addr, SignSettings::default())?;

    let mut tshark = resolver.eavesdrop()?;

    let resolver_addr = resolver.ipv4_addr();

    let client = Client::new(resolver.network())?;
    let client_addr = client.ipv4_addr();
    let settings = *DigSettings::default().recurse().authentic_data();
    let _output = client.dig(settings, resolver_addr, RecordType::A, &leaf_fqdn)?;

    tshark.wait_until(
        |captures| {
            captures.iter().any(|Capture { direction, .. }| {
                matches!(
                    direction,
                    Direction::Outgoing {
                        destination
                    } if *destination == client_addr
                )
            })
        },
        Duration::from_secs(10),
    )?;
    let captures = tshark.terminate()?;

    let mut ns_checks_count = 0;
    let mut client_checks_count = 0;
    let ns_addrs = nameservers
        .iter()
        .map(|ns| ns.ipv4_addr())
        .collect::<Vec<_>>();
    for Capture { message, direction } in captures {
        match direction {
            Direction::Incoming { source } => {
                if source == client_addr {
                    // sanity check
                    assert!(message.is_ad_flag_set());

                    client_checks_count += 1;
                }
            }

            Direction::Outgoing { destination } => {
                if destination == client_addr {
                    // skip response to client
                    continue;
                }

                // sanity check
                assert!(ns_addrs.contains(&destination));

                assert!(!message.is_ad_flag_set());

                ns_checks_count += 1;
            }
        }
    }

    // sanity checks
    assert_eq!(1, client_checks_count);
    assert_ne!(0, dbg!(ns_checks_count));

    Ok(())
}
