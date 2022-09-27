//! Official implementation of the IPGen Spec
//!
//! This library is the official reference implementation
//! of the [IPGen Spec] for generating unique and reproducible
//! IPv4 and IPv6 addresses.
//!
//! It exposes only two simple functions `ip` and `subnet`.
//!
//! [IPGen Spec]: https://github.com/ipgen/spec
mod error;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ipnetwork::Ipv6Network;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

const IP4_PREFIX: u8 = 32;
const IP6_PREFIX: u8 = 128;

/// An IP network address typically in CIDR format
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpNetwork(ipnetwork::IpNetwork);

impl FromStr for IpNetwork {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(s.parse()?))
    }
}

/// Generates an IP address
///
/// Takes any string and a IPv4 or IPv6 network local address
/// eg `fd52:f6b0:3162::/64` or `10.0.0.0/8` and computes a unique IP address.
pub fn ip(name: &str, net: IpNetwork) -> Result<IpAddr> {
    match net.0 {
        // handle IPv6 address
        ipnetwork::IpNetwork::V6(net6) => {
            if net6.prefix() == IP6_PREFIX {
                return Err(Error::PrefixTooBig(net));
            }
            ip6(name, net6).map(IpAddr::V6)
        }
        // handle IPv4 address
        ipnetwork::IpNetwork::V4(net4) => {
            if net4.prefix() == IP4_PREFIX {
                return Err(Error::PrefixTooBig(net));
            }
            let prefix = IP6_PREFIX - IP4_PREFIX + net4.prefix();
            let net6 = format!("::{}/{prefix}", net4.ip()).parse::<Ipv6Network>()?;
            let ipv6_addr = ip6(name, net6)?.to_string();
            let ip_addr = ipv6_addr
                .strip_prefix("::")
                // This error should never happen but I'm not a fan of panicking in libraries
                .ok_or_else(|| Error::InvalidIpNetwork(format!("[BUG] the generated IPv6 address `{ipv6_addr}` does not start with the expected prefix `::`")))?
                .parse()
                // This error should never happen but I'm not a fan of panicking in libraries
                .map_err(|_| Error::InvalidIpNetwork(format!("[BUG] failed to parse the generated IP address `{}` as IPv4", ipv6_addr.trim_start_matches(':'))))
                ?;
            Ok(IpAddr::V4(ip_addr))
        }
    }
}

// Generates an IPv6 address from an IPv6 network
fn ip6(name: &str, net: Ipv6Network) -> Result<Ipv6Addr> {
    // If we divide the prefix by 4 we will get the total number
    // of characters that we must never touch.
    let network_len = net.prefix() as usize / 4;
    let ip = net.ip().segments();
    // Uncompress the IP address and throw away the semi-colons
    // so we can easily extract the network part and later
    // join it to the address part that we will compute.
    let ip_parts: Vec<String> = ip.iter().map(|b| format!("{b:04x}")).collect();
    let ip_hash = ip_parts.join("");
    let network_hash = &ip_hash[..network_len];
    // The number of characters we need to generate
    //
    // * An IPv6 address has a total number of 32 (8*4) characters.
    // * Subtracting those characters from the total in an IP address
    //   gives us the number of characters we need to generate.
    let address_len = 32 - network_len;
    // Blake2b generates hashes in multiples of 2 so we need to divide
    // the total number of characters we need by 2. However, to fully
    // utilise the address space available to us, if this leaves a
    // remainder (which will always be 1) we add it back to output length
    // and then discard the last character of the resulting hash.
    let blake_len = (address_len / 2) + (address_len % 2);
    let address_hash = hash(name.as_bytes(), blake_len)?;
    let ip_hash = format!("{}{}", network_hash, address_hash);
    let ip_str = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        &ip_hash[..4],
        &ip_hash[4..8],
        &ip_hash[8..12],
        &ip_hash[12..16],
        &ip_hash[16..20],
        &ip_hash[20..24],
        &ip_hash[24..28],
        &ip_hash[28..32]
    );
    let ip_addr = ip_str.parse().map_err(|_| {
        // This error should never happen but I'm not a fan of panicking in libraries
        Error::InvalidIpNetwork(format!(
            "[BUG] failed to parse the generated IP string `{ip_str}` as IPv6",
        ))
    })?;
    Ok(ip_addr)
}

/// Computes a subnet ID for any identifier
pub fn subnet(name: &str) -> Result<String> {
    hash(name.as_bytes(), 2)
}

fn hash(name: &[u8], len: usize) -> Result<String> {
    let mut hasher = Blake2bVar::new(len)
        // This error should never happen but I'm not a fan of panicking in libraries
        .map_err(|_| {
            Error::InvalidIpNetwork(format!(
                "[BUG] output length of {len} resulted in an error in hash generation",
            ))
        })?;
    hasher.update(name);
    let mut buf = vec![0u8; len];
    hasher.finalize_variable(&mut buf).map_err(|_| {
        Error::InvalidIpNetwork(format!(
            "[BUG] buffer size of {len} resulted in an error in hash generation",
        ))
    })?;
    Ok(buf.iter().map(|v| format!("{:02x}", v)).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ip_generation() {
        // IPv6
        let ip = crate::ip("cassandra.1", "fd9d:bb35:94bf::/48".parse().unwrap())
            .unwrap()
            .to_string();
        assert_eq!(ip, "fd9d:bb35:94bf:c38a:ee1:c75d:8df3:c909");

        // IPv4
        let ip = crate::ip("postgresql.host1", "10.0.0.0/8".parse().unwrap())
            .unwrap()
            .to_string();
        assert_eq!(ip, "10.102.194.34");

        // an empty name
        let ip = crate::ip("", "fd9d:bb35:94bf::/48".parse().unwrap())
            .unwrap()
            .to_string();
        assert_eq!(ip, "fd9d:bb35:94bf:6fa1:d8fc:fd71:9046:d762");

        // an empty name
        let ip = crate::ip("", "fd9d:bb35:94bf::/48".parse().unwrap())
            .unwrap()
            .to_string();
        assert_eq!(ip, "fd9d:bb35:94bf:6fa1:d8fc:fd71:9046:d762");
    }

    #[test]
    fn subnet_generation() {
        let subnet = crate::subnet("consul").unwrap();
        assert_eq!(subnet, "1211");
    }
}
