// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! HTTPS related server items

use alloc::sync::Arc;
use core::fmt::Debug;
use core::str::FromStr;

use bytes::{Bytes, BytesMut};
use futures_util::stream::{Stream, StreamExt};
use h2;
use http::header::CONTENT_LENGTH;
use http::{Method, Request};
use tracing::debug;

use crate::h2::HttpsError;
use crate::http::Version;

/// Given an HTTP request, return a future that will result in the next sequence of bytes.
///
/// To allow downstream clients to do something interesting with the lifetime of the bytes, this doesn't
///   perform a conversion to a Message, only collects all the bytes.
pub async fn message_from<R>(
    this_server_name: Option<Arc<str>>,
    this_server_endpoint: Arc<str>,
    request: Request<R>,
) -> Result<BytesMut, HttpsError>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Debug + Unpin,
{
    debug!("Received request: {:#?}", request);

    let this_server_name = this_server_name.as_deref();
    match crate::http::request::verify(
        Version::Http2,
        this_server_name,
        &this_server_endpoint,
        &request,
    ) {
        Ok(_) => (),
        Err(err) => return Err(err),
    }

    // attempt to get the content length
    let mut content_length = None;
    if let Some(length) = request.headers().get(CONTENT_LENGTH) {
        let length = usize::from_str(length.to_str()?)?;
        debug!("got message length: {}", length);
        content_length = Some(length);
    }

    match *request.method() {
        Method::GET => Err(format!("GET unimplemented: {}", request.method()).into()),
        Method::POST => message_from_post(request.into_body(), content_length).await,
        _ => Err(format!("bad method: {}", request.method()).into()),
    }
}

/// Deserialize the message from a POST message
pub(crate) async fn message_from_post<R>(
    mut request_stream: R,
    length: Option<usize>,
) -> Result<BytesMut, HttpsError>
where
    R: Stream<Item = Result<Bytes, h2::Error>> + 'static + Send + Debug + Unpin,
{
    let mut bytes = BytesMut::with_capacity(length.unwrap_or(0).clamp(512, 4_096));

    loop {
        match request_stream.next().await {
            Some(Ok(mut frame)) => bytes.extend_from_slice(&frame.split_off(0)),
            Some(Err(err)) => return Err(err.into()),
            None => {
                return if let Some(length) = length {
                    // wait until we have all the bytes
                    if bytes.len() == length {
                        Ok(bytes)
                    } else {
                        Err("not all bytes received".into())
                    }
                } else {
                    Ok(bytes)
                };
            }
        };

        if let Some(length) = length {
            // wait until we have all the bytes
            if bytes.len() == length {
                return Ok(bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use futures_executor::block_on;

    use test_support::subscribe;

    use crate::http::request;
    use crate::op::Message;

    use super::*;

    #[derive(Debug)]
    struct TestBytesStream(Vec<Result<Bytes, h2::Error>>);

    impl Stream for TestBytesStream {
        type Item = Result<Bytes, h2::Error>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.0.pop() {
                Some(Ok(bytes)) => Poll::Ready(Some(Ok(bytes))),
                Some(Err(err)) => Poll::Ready(Some(Err(err))),
                None => Poll::Ready(None),
            }
        }
    }

    #[test]
    fn test_from_post() {
        subscribe();
        let message = Message::query();
        let msg_bytes = message.to_vec().unwrap();
        let len = msg_bytes.len();
        let stream = TestBytesStream(vec![Ok(Bytes::from(msg_bytes))]);
        let request = request::new(Version::Http2, "ns.example.com", "/dns-query", len).unwrap();
        let request = request.map(|()| stream);

        let from_post = message_from(
            Some(Arc::from("ns.example.com")),
            "/dns-query".into(),
            request,
        );
        let bytes = match block_on(from_post) {
            Ok(bytes) => bytes,
            e => panic!("{:#?}", e),
        };

        let msg_from_post = Message::from_vec(bytes.as_ref()).expect("bytes failed");
        assert_eq!(message, msg_from_post);
    }
}
