use ipnetwork::IpNetworkError;
use std::{error, fmt};

/// Errors returned by this crate
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Error {
    /// The IP network address provided is invalid
    ///
    /// *NB:* for some unseen reason, the network and ip addresses
    /// generated internally by this crate might fail to parse.
    /// This is is obviously a bug and as such, are labelled `[BUG]`.
    /// If you run into these kindly report them on the repo.
    InvalidIpNetwork(String),
    /// Network address provided is already a full IP address
    PrefixTooBig(crate::IpNetwork),
    /// Failed to parse string
    ParseFailed(String),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidIpNetwork(error) | Error::ParseFailed(error) => write!(f, "{}", error),
            Error::PrefixTooBig(crate::IpNetwork(net)) => write!(
                f,
                "{}/{} is already a full IP address",
                net.ip(),
                net.prefix()
            ),
        }
    }
}

impl From<IpNetworkError> for Error {
    fn from(error: IpNetworkError) -> Self {
        Self::InvalidIpNetwork(error.to_string())
    }
}
