//! The HTTP client every request to the OAuth server goes through.

use std::io::Read;
use std::time::Duration;

use curl::easy::Easy;
use oauth2::http::header::{HeaderValue, CONTENT_TYPE};
use oauth2::http::method::Method;
use oauth2::http::status::StatusCode;
use oauth2::{HttpClientError, HttpRequest, HttpResponse, SyncHttpClient};

/// `oauth2::CurlHttpClient` with a bound on each request.
///
/// The crate's client sets no timeout, so libcurl waits indefinitely for a
/// server that accepts the connection and never answers, and with it the PAM
/// conversation and the service that called it. `timeout` bounds the whole
/// request, connect included (`CURLOPT_TIMEOUT`).
#[derive(Debug, Clone, Copy)]
pub struct TimedCurlClient {
    pub timeout: Duration,
}

impl SyncHttpClient for TimedCurlClient {
    type Error = HttpClientError<curl::Error>;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let mut easy = Easy::new();
        easy.url(&request.uri().to_string()[..]).map_err(Box::new)?;
        easy.timeout(self.timeout).map_err(Box::new)?;

        let mut headers = curl::easy::List::new();
        for (name, value) in request.headers() {
            let value = value.to_str().map_err(|_| {
                HttpClientError::Other(format!(
                    "invalid `{name}` header value {:?}",
                    value.as_bytes()
                ))
            })?;
            headers
                .append(&format!("{name}: {value}"))
                .map_err(Box::new)?;
        }
        easy.http_headers(headers).map_err(Box::new)?;

        if let Method::POST = *request.method() {
            easy.post(true).map_err(Box::new)?;
            easy.post_field_size(request.body().len() as u64)
                .map_err(Box::new)?;
        } else if *request.method() != Method::GET {
            return Err(HttpClientError::Other(format!(
                "unsupported method {}",
                request.method()
            )));
        }

        let mut form_slice = &request.body()[..];
        let mut data = Vec::new();
        {
            let mut transfer = easy.transfer();
            transfer
                .read_function(|buf| Ok(form_slice.read(buf).unwrap_or(0)))
                .map_err(Box::new)?;
            transfer
                .write_function(|new_data| {
                    data.extend_from_slice(new_data);
                    Ok(new_data.len())
                })
                .map_err(Box::new)?;
            transfer.perform().map_err(Box::new)?;
        }

        let mut builder = oauth2::http::Response::builder().status(
            StatusCode::from_u16(easy.response_code().map_err(Box::new)? as u16)
                .map_err(oauth2::http::Error::from)?,
        );
        if let Some(content_type) = easy
            .content_type()
            .map_err(Box::new)?
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(oauth2::http::Error::from)?
        {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        builder.body(data).map_err(HttpClientError::Http)
    }
}
