use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use futures::Future;

/// A value that returns `Ready()` if internal value is true, otherwise `Pending`.
/// Can be used inside `tokio::select!` macros.
#[derive(Debug, Copy, Clone)]
pub struct BoolFuture(pub bool);

impl Future for BoolFuture {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Self::Output> {
        if self.0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
