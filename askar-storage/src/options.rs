use std::borrow::Cow;
use std::collections::HashMap;

use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};

use crate::error::Error;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// Parsed representation of database connection URI
pub struct Options<'a> {
    /// The URI schema
    pub scheme: Cow<'a, str>,
    /// The authenticating user name
    pub user: Cow<'a, str>,
    /// The authenticating user password
    pub password: Cow<'a, str>,
    /// The host name
    pub host: Cow<'a, str>,
    /// The path component
    pub path: Cow<'a, str>,
    /// The query component
    pub query: HashMap<String, String>,
    /// The fragment component
    pub fragment: Cow<'a, str>,
}

impl Options<'_> {
    /// Parse a URI string into an Options structure
    pub fn parse_uri(uri: &str) -> Result<Options<'_>, Error> {
        let mut fragment_and_remain = uri.splitn(2, '#');
        let uri = fragment_and_remain.next().unwrap_or_default();
        let fragment = percent_decode(fragment_and_remain.next().unwrap_or_default());
        let mut scheme_and_remain = uri.splitn(2, ':');
        let scheme = scheme_and_remain.next().unwrap_or_default();

        let (scheme, host_and_query) = if let Some(remain) = scheme_and_remain.next() {
            if scheme.is_empty() {
                ("", uri)
            } else {
                (scheme, remain.trim_start_matches("//"))
            }
        } else {
            ("", uri)
        };
        let scheme = percent_decode(scheme);

        let mut host_and_query = host_and_query.splitn(2, '?');
        let (user, password, host) = {
            let mut user_and_host = host_and_query.next().unwrap_or_default().splitn(2, '@');
            let user_pass = user_and_host.next().unwrap_or_default();
            if let Some(host) = user_and_host.next() {
                let mut user_pass = user_pass.splitn(2, ':');
                let user = percent_decode(user_pass.next().unwrap_or_default());
                let pass = percent_decode(user_pass.next().unwrap_or_default());
                (user, pass, host)
            } else {
                (Cow::Borrowed(""), Cow::Borrowed(""), user_pass)
            }
        };
        let (host, path) = if let Some(path_pos) = host.find('/') {
            (
                percent_decode(&host[..path_pos]),
                percent_decode(&host[path_pos..]),
            )
        } else {
            (percent_decode(host), Cow::Borrowed(""))
        };

        let query = if let Some(query) = host_and_query.next() {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .fold(HashMap::new(), |mut map, (k, v)| {
                    map.insert(k, v);
                    map
                })
        } else {
            HashMap::new()
        };

        Ok(Options {
            user,
            password,
            host,
            path,
            scheme,
            query,
            fragment,
        })
    }

    /// Convert an options structure back into a string
    pub fn into_uri(self) -> String {
        let mut uri = String::new();
        if !self.scheme.is_empty() {
            percent_encode_into(&mut uri, &self.scheme);
            uri.push_str("://");
        }
        if !self.user.is_empty() || !self.password.is_empty() {
            percent_encode_into(&mut uri, &self.user);
            uri.push(':');
            percent_encode_into(&mut uri, &self.password);
            uri.push('@');
        }
        uri.push_str(&self.host);
        uri.push_str(&self.path);
        if !self.query.is_empty() {
            uri.push('?');
            for (k, v) in self.query {
                push_iter_str(&mut uri, url::form_urlencoded::byte_serialize(k.as_bytes()));
                uri.push('=');
                push_iter_str(&mut uri, url::form_urlencoded::byte_serialize(v.as_bytes()));
            }
        }
        if !self.fragment.is_empty() {
            uri.push('#');
            percent_encode_into(&mut uri, &self.fragment);
        }
        uri
    }
}

#[inline]
fn push_iter_str<'a, I: Iterator<Item = &'a str>>(s: &mut String, iter: I) {
    for item in iter {
        s.push_str(item);
    }
}

#[inline]
fn percent_decode(s: &str) -> Cow<'_, str> {
    percent_decode_str(s).decode_utf8_lossy()
}

#[inline]
fn percent_encode_into(result: &mut String, s: &str) {
    push_iter_str(result, utf8_percent_encode(s, NON_ALPHANUMERIC))
}

/// A trait implemented by types that can be converted into Options
pub trait IntoOptions<'a> {
    /// Try to convert self into an Options structure
    fn into_options(self) -> Result<Options<'a>, Error>;
}

impl<'a> IntoOptions<'a> for Options<'a> {
    fn into_options(self) -> Result<Options<'a>, Error> {
        Ok(self)
    }
}

impl<'a> IntoOptions<'a> for &'a str {
    fn into_options(self) -> Result<Options<'a>, Error> {
        Options::parse_uri(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_basic() {
        let opts = Options::parse_uri("scheme://user%2E:pass@host/dbname?a+1=b#frag").unwrap();
        let bs = Cow::Borrowed;
        assert_eq!(
            opts,
            Options {
                user: bs("user."),
                password: bs("pass"),
                scheme: bs("scheme"),
                host: bs("host"),
                path: bs("/dbname"),
                query: HashMap::from_iter(vec![("a 1".to_owned(), "b".to_owned())]),
                fragment: bs("frag"),
            }
        );
    }

    #[test]
    fn options_no_schema() {
        let opts = Options::parse_uri("dbname/path?a#frag").unwrap();
        assert_eq!(
            opts,
            Options {
                user: Default::default(),
                password: Default::default(),
                scheme: Default::default(),
                host: Cow::Borrowed("dbname"),
                path: Cow::Borrowed("/path"),
                query: HashMap::from_iter(vec![("a".to_owned(), "".to_owned())]),
                fragment: Cow::Borrowed("frag")
            }
        );
    }

    #[test]
    fn options_round_trip() {
        let opts_str = "schema://user%2F:pass@dbname?a+1=b#frag%2E";
        let opts = Options::parse_uri(opts_str).unwrap();
        assert_eq!(opts.into_uri(), opts_str);
    }
}
