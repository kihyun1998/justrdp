#![forbid(unsafe_code)]

//! Reference WebSocket transport.
//!
//! Compiled only for `wasm32` + `feature = "websocket"`. Bridges the
//! browser `web_sys::WebSocket` event API into the async [`WebTransport`]
//! contract by buffering inbound frames in a single-threaded `RefCell`
//! and waking pending `recv()` futures from the message callback.
//!
//! Single-threaded by design: wasm32 in browsers is single-threaded, so a
//! `Mutex` would only add cost. Cross-Worker scenarios should run a
//! separate transport instance per Worker.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Poll, Waker};

use js_sys::{Array, ArrayBuffer, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

use crate::error::TransportError;
use crate::transport::WebTransport;

/// Configuration for opening a [`WebSocketTransport`].
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    pub url: String,
    /// WebSocket subprotocols offered to the server (`Sec-WebSocket-Protocol`).
    /// Empty means none, which matches the most common bridge setup.
    pub subprotocols: Vec<String>,
}

impl WebSocketConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            subprotocols: Vec::new(),
        }
    }

    pub fn with_subprotocol(mut self, name: impl Into<String>) -> Self {
        self.subprotocols.push(name.into());
        self
    }
}

/// `web_sys::WebSocket` adapter implementing [`WebTransport`].
pub struct WebSocketTransport {
    socket: WebSocket,
    inner: Rc<RefCell<Inner>>,
    // The closures must outlive the WebSocket they are attached to;
    // dropping `WebSocketTransport` drops them, which detaches the
    // listeners cleanly via wasm-bindgen's `Drop` impl.
    _onopen: Closure<dyn FnMut(Event)>,
    _onmessage: Closure<dyn FnMut(MessageEvent)>,
    _onerror: Closure<dyn FnMut(Event)>,
    _onclose: Closure<dyn FnMut(CloseEvent)>,
}

struct Inner {
    queue: VecDeque<Vec<u8>>,
    error: Option<TransportError>,
    open: bool,
    closed: bool,
    open_waker: Option<Waker>,
    recv_waker: Option<Waker>,
}

impl Inner {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            error: None,
            open: false,
            closed: false,
            open_waker: None,
            recv_waker: None,
        }
    }

    fn wake_open(&mut self) {
        if let Some(w) = self.open_waker.take() {
            w.wake();
        }
    }

    fn wake_recv(&mut self) {
        if let Some(w) = self.recv_waker.take() {
            w.wake();
        }
    }
}

impl WebSocketTransport {
    /// Open a WebSocket and resolve once the open handshake completes.
    pub async fn connect(config: WebSocketConfig) -> Result<Self, TransportError> {
        let socket = if config.subprotocols.is_empty() {
            WebSocket::new(&config.url)
        } else {
            let arr = Array::new();
            for proto in &config.subprotocols {
                arr.push(&JsValue::from_str(proto));
            }
            WebSocket::new_with_str_sequence(&config.url, &arr)
        }
        .map_err(|e| TransportError::io(js_to_string(&e)))?;
        socket.set_binary_type(BinaryType::Arraybuffer);

        let inner = Rc::new(RefCell::new(Inner::new()));

        let onopen = {
            let inner = Rc::clone(&inner);
            Closure::<dyn FnMut(Event)>::new(move |_evt: Event| {
                let mut g = inner.borrow_mut();
                g.open = true;
                g.wake_open();
            })
        };
        socket.set_onopen(Some(onopen.as_ref().unchecked_ref()));

        let onmessage = {
            let inner = Rc::clone(&inner);
            Closure::<dyn FnMut(MessageEvent)>::new(move |evt: MessageEvent| {
                let data = evt.data();
                match data.dyn_into::<ArrayBuffer>() {
                    Ok(buf) => {
                        let bytes = Uint8Array::new(&buf).to_vec();
                        let mut g = inner.borrow_mut();
                        g.queue.push_back(bytes);
                        g.wake_recv();
                    }
                    Err(_) => {
                        // The bridge sent a non-binary frame. RDP is binary
                        // only — record the error and wake any pending
                        // recv() so the connector can surface it.
                        let mut g = inner.borrow_mut();
                        g.error
                            .get_or_insert_with(|| TransportError::protocol("non-binary WS message"));
                        g.wake_recv();
                    }
                }
            })
        };
        socket.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        let onerror = {
            let inner = Rc::clone(&inner);
            Closure::<dyn FnMut(Event)>::new(move |_evt: Event| {
                let mut g = inner.borrow_mut();
                g.error
                    .get_or_insert_with(|| TransportError::io("websocket error event"));
                g.wake_open();
                g.wake_recv();
            })
        };
        socket.set_onerror(Some(onerror.as_ref().unchecked_ref()));

        let onclose = {
            let inner = Rc::clone(&inner);
            Closure::<dyn FnMut(CloseEvent)>::new(move |evt: CloseEvent| {
                let mut g = inner.borrow_mut();
                g.closed = true;
                if !evt.was_clean() {
                    let msg = format!(
                        "ws closed code={} reason={}",
                        evt.code(),
                        evt.reason()
                    );
                    g.error.get_or_insert_with(|| TransportError::closed(msg));
                }
                g.wake_open();
                g.wake_recv();
            })
        };
        socket.set_onclose(Some(onclose.as_ref().unchecked_ref()));

        // Block until either onopen fires, an error is recorded, or the
        // socket closes before opening.
        {
            let inner_ref = Rc::clone(&inner);
            poll_fn(move |cx| {
                let mut g = inner_ref.borrow_mut();
                if let Some(err) = g.error.take() {
                    return Poll::Ready(Err(err));
                }
                if g.open {
                    return Poll::Ready(Ok(()));
                }
                if g.closed {
                    return Poll::Ready(Err(TransportError::closed("ws closed before open")));
                }
                g.open_waker = Some(cx.waker().clone());
                Poll::Pending
            })
            .await?;
        }

        Ok(Self {
            socket,
            inner,
            _onopen: onopen,
            _onmessage: onmessage,
            _onerror: onerror,
            _onclose: onclose,
        })
    }
}

impl WebTransport for WebSocketTransport {
    async fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        {
            let mut g = self.inner.borrow_mut();
            if let Some(err) = g.error.take() {
                return Err(err);
            }
            if g.closed {
                return Err(TransportError::closed("ws closed"));
            }
        }
        self.socket
            .send_with_u8_array(bytes)
            .map_err(|e| TransportError::io(js_to_string(&e)))
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let inner = Rc::clone(&self.inner);
        poll_fn(move |cx| {
            let mut g = inner.borrow_mut();
            if let Some(err) = g.error.take() {
                return Poll::Ready(Err(err));
            }
            if let Some(frame) = g.queue.pop_front() {
                return Poll::Ready(Ok(frame));
            }
            if g.closed {
                return Poll::Ready(Err(TransportError::closed("ws closed")));
            }
            g.recv_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        let _ = self.socket.close();
        self.inner.borrow_mut().closed = true;
        Ok(())
    }
}

fn js_to_string(v: &JsValue) -> String {
    v.as_string().unwrap_or_else(|| {
        // JsValue Debug rendering is good enough for diagnostics — this
        // path is hit when the browser hands us a non-string error
        // (e.g. a DOMException object).
        format!("{v:?}")
    })
}
