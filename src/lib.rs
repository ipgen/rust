//! Official implementation of the IPGen Spec
//!
//! This library is the official reference implementation
//! of the [IPGen Spec] for generating unique and reproducible
//! IPv4 and IPv6 addresses.
//!
//! It exposes only two simple functions `ip` and `subnet`.
//!
//! [IPGen Spec]: https://github.com/ipgen/spec
use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;
use ipnetwork::{Ipv4Network, Ipv6Network};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Generates an IP address
///
/// Takes any string and a IPv4 or IPv6 network local address
/// eg `fd52:f6b0:3162::/64` or `10.0.0.0/8` and computes a unique IP address.
pub fn ip(name: &str, cidr: &str) -> Result<IpAddr, String> {
    let ip_addr = match IpAddr::from_str(cidr.split("/").collect::<Vec<&str>>()[0])
        .map_err(|err| err.to_string())
    {
        Ok(ip_addr) => ip_addr,
        Err(msg) => return Err(msg),
    };
    match ip_addr {
        // handle IPv6 address
        IpAddr::V6(_) => {
            match Ipv6Network::from_str(cidr).map_err(|err| format!("{:?}", err)) {
                Ok(net) => {
                    if net.prefix() == 128 {
                        return Err(format!(
                            "{}/{} is already a full IPv6 address",
                            net.ip(),
                            net.prefix()
                        ));
                    };
                    return ip6(name, net).map(|ip| IpAddr::V6(ip));
                }
                Err(msg) => return Err(msg),
            };
        }
        // handle IPv4 address
        IpAddr::V4(_) => {
            match Ipv4Network::from_str(cidr).map_err(|err| format!("{:?}", err)) {
                Ok(net) => {
                    if net.prefix() == 32 {
                        return Err(format!(
                            "{}/{} is already a full IPv4 address",
                            net.ip(),
                            net.prefix()
                        ));
                    };
                    let ip6prefix = 128 - 32 + net.prefix();
                    let ip6net = format!("::{}/{}", net.ip(), ip6prefix);
                    match Ipv6Network::from_str(ip6net.as_str()).map_err(|err| format!("{:?}", err))
                    {
                        Ok(net) => match ip6(name, net) {
                            Ok(a) => {
                                let a = a.to_string();
                                let addr = a.split("::").collect::<Vec<&str>>()[1];
                                match Ipv4Addr::from_str(addr) {
                                    Ok(ip) => return Ok(IpAddr::V4(ip)),
                                    Err(msg) => {
                                        return Err(format!(
                                            "generated IPv4 address ({}) has \
                                                                {}",
                                            addr, msg
                                        ))
                                    }
                                };
                            }
                            Err(msg) => return Err(msg),
                        },
                        Err(msg) => return Err(msg),
                    };
                }
                Err(msg) => return Err(msg),
            };
        }
    };
}

// Generates an IPv6 address from an IPv6 network
fn ip6(name: &str, net: Ipv6Network) -> Result<Ipv6Addr, String> {
    // If we divide the prefix by 4 we will get the total number
    // of characters that we must never touch.
    let network_len = net.prefix() as usize / 4;
    let ip = net.ip().segments();
    // Uncompress the IP address and throw away the semi-colons
    // so we can easily join extract the network part and later
    // join it to the address part that we will compute.
    let ip_parts: Vec<String> = ip.iter().map(|b| format!("{:04x}", b)).collect();
    let ip_hash = ip_parts.join("");
    let ip_hash = ip_hash.as_str();
    let network_hash = &ip_hash[0..network_len];
    // The number of characters we need to generate
    //
    // * An IPv6 address has a total number of 32 (8*4) characters.
    // * Subtracting those characters from the total in an IP address
    //   gives us the number of characters we need to generate.
    let address_len = 32 - network_len;
    // Blake2b generates hashes in multiples of 2 so we need to divide
    // the total number of characters we need by 2. However, to fully
    // utilise the address space available to us, if this leaves a
    // remainder (which will aways be 1) we add it back to output length
    // and then discard the last character of the resulting hash.
    let blake_len = (address_len / 2) + (address_len % 2);
    let address_hash = hash(name.as_bytes(), blake_len);
    let ip_hash = format!("{}{}", network_hash, address_hash);
    let ip = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        &ip_hash[0..4],
        &ip_hash[4..8],
        &ip_hash[8..12],
        &ip_hash[12..16],
        &ip_hash[16..20],
        &ip_hash[20..24],
        &ip_hash[24..28],
        &ip_hash[28..32]
    );
    Ipv6Addr::from_str(ip.as_str())
        .map_err(|err| format!("generated IPv6 address ({}) has {}", ip, err))
}

/// Computes a subnet ID for any identifier
pub fn subnet(name: &str) -> String {
    hash(name.as_bytes(), 2)
}

fn hash(name: &[u8], len: usize) -> String {
    let mut hasher = VarBlake2b::new(len).unwrap();
    hasher.update(name);
    let mut hash = String::with_capacity(len);
    hasher.finalize_variable(|res| {
        hash = res.iter().map(|v| format!("{:02x}", v)).collect();
    });
    hash
}
