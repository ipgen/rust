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
use std::cmp::Ordering::{Equal, Greater, Less};
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
        // Handle IPv6 address
        ipnetwork::IpNetwork::V6(net6) => match net6.prefix().cmp(&IP6_PREFIX) {
            Less => Ok(IpAddr::V6(ip6(name, net6)?)),
            Equal => Ok(IpAddr::V6(net6.ip())),
            Greater => Err(Error::PrefixTooBig(net)),
        },
        // Handle IPv4 address
        ipnetwork::IpNetwork::V4(net4) => match net4.prefix().cmp(&IP4_PREFIX) {
            Less => {
                let prefix = IP6_PREFIX - IP4_PREFIX + net4.prefix();
                let net6 = Ipv6Network::new(net4.ip().to_ipv6_mapped(), prefix)?;
                Ok(IpAddr::V4(ip6(name, net6)?.to_ipv4_mapped().unwrap()))
            }
            Equal => Ok(IpAddr::V4(net4.ip())),
            Greater => Err(Error::PrefixTooBig(net)),
        },
    }
}

// Generates an IPv6 address from an IPv6 network
fn ip6(name: &str, net: Ipv6Network) -> Result<Ipv6Addr> {
    // Get the number of bits that will be preserved as the network prefix
    let network_len = net.prefix() as usize;

    // Convert the address to a u128
    let network_hash = net.ip().to_bits();

    // The number of bits we need to generate
    //
    // * An IPv6 address has a total number of 128 bits.
    // * Subtracting the network prefix length from the total in an IP address
    //   gives us the number of bits we need to generate.
    let address_len = IP6_PREFIX as usize - network_len;

    // Get the hash of `name`
    let address_hash = hash(name.as_bytes(), address_len)?;

    // Join the network and address hashes via bitmasking
    let ip_hash = network_hash | address_hash;

    Ok(Ipv6Addr::from_bits(ip_hash))
}

/// Computes a subnet ID for any identifier
pub fn subnet(name: &str) -> Result<String> {
    Ok(format!("{:x}", hash(name.as_bytes(), 16)?))
}

/// Hashes a given slice of bytes (`name`) to a string of size `len`
fn hash(name: &[u8], bits: usize) -> Result<u128> {
    // Convert # of bits to # of bytes
    let len = (bits / 8) + (bits % 8 != 0) as usize;

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

    // Fit `buf` into a [u8; 16], prepadded with zeros
    let bytes: [u8; 16] = {
        let mut bytes = [0u8; 16];
        bytes[16 - buf.len()..].copy_from_slice(&buf[..]);
        bytes
    };

    let res = u128::from_be_bytes(bytes) & (u128::MAX >> (IP6_PREFIX as usize - bits));

    Ok(res)
}

#[cfg(test)]
mod tests {
    use crate::IpNetwork;

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
    fn test_ipv4_extensive() {
        // Makes sure that the generated addresses are within the network
        for s in 0..1000 {
            let net: IpNetwork = "10.0.0.3/25".parse().unwrap();
            let addr = crate::ip(&s.to_string(), net).unwrap();
            assert!(net.0.contains(addr));
        }
    }

    #[test]
    fn subnet_generation() {
        let subnet = crate::subnet("consul").unwrap();
        assert_eq!(subnet, "1211");
    }
}
