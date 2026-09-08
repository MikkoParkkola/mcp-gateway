// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Private request queues. Notifications keep their existing broadcast path.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::sync::mpsc;

use super::ClientSession;
use crate::gateway::input_bridge::DeliveryProgress;

#[derive(Debug)]
pub(crate) struct QueuedRequest {
    pub(crate) json: String,
    pub(crate) delivery: Arc<DeliveryProgress>,
}

impl Drop for QueuedRequest {
    fn drop(&mut self) {
        self.delivery.fail_unfinished_frame();
    }
}

/// Transport liveness only: response senders remain solely in `ProxyManager`.
#[derive(Debug, Default)]
struct WriterDeliveries(Mutex<HashMap<String, Arc<DeliveryProgress>>>);

impl WriterDeliveries {
    fn fail_all(&self) {
        let deliveries = std::mem::take(&mut *self.0.lock());
        for progress in deliveries.into_values() {
            progress.fail();
        }
    }
}

#[derive(Debug)]
struct Registration {
    sender: mpsc::Sender<QueuedRequest>,
    deliveries: Arc<WriterDeliveries>,
}

#[derive(Debug, Default)]
struct Registry {
    next_id: u64,
    closed: bool,
    writers: BTreeMap<u64, Registration>,
}

#[derive(Debug, Default)]
pub(super) struct RequestWriters(Mutex<Registry>);

impl RequestWriters {
    pub(super) fn register(
        &self,
        session: &Arc<ClientSession>,
        capacity: usize,
    ) -> Option<RequestWriter> {
        let mut registry = self.0.lock();
        if registry.closed || capacity == 0 {
            return None;
        }
        let writer_id = registry.next_id.checked_add(1)?;
        registry.next_id = writer_id;
        let (sender, receiver) = mpsc::channel(capacity);
        let deliveries = Arc::new(WriterDeliveries::default());
        registry.writers.insert(
            writer_id,
            Registration {
                sender,
                deliveries: Arc::clone(&deliveries),
            },
        );
        Some(RequestWriter {
            session: Arc::downgrade(session),
            writer_id,
            deliveries,
            receiver,
        })
    }

    pub(super) fn send(
        &self,
        id: &str,
        json: String,
        delivery: Arc<DeliveryProgress>,
    ) -> Option<DeliveryLease> {
        let registry = self.0.lock();
        let mut frame = QueuedRequest { json, delivery };
        for registration in registry.writers.values() {
            registration
                .deliveries
                .0
                .lock()
                .insert(id.to_string(), Arc::clone(&frame.delivery));
            match registration.sender.try_send(frame) {
                Ok(()) => {
                    return Some(DeliveryLease {
                        deliveries: Arc::downgrade(&registration.deliveries),
                        id: id.to_string(),
                    });
                }
                Err(error) => {
                    registration.deliveries.0.lock().remove(id);
                    // Full/closed queues prove non-delivery; only this path
                    // can select another writer. Successful enqueue is final.
                    frame = error.into_inner();
                }
            }
        }
        None
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.lock().writers.is_empty()
    }

    pub(super) fn close(&self) {
        let registrations = {
            let mut registry = self.0.lock();
            registry.closed = true;
            std::mem::take(&mut registry.writers)
        };
        for registration in registrations.into_values() {
            registration.deliveries.fail_all();
        }
    }
}

impl Drop for RequestWriters {
    fn drop(&mut self) {
        self.close();
    }
}

/// Held by the existing pending-request guard until that exchange ends.
pub(crate) struct DeliveryLease {
    deliveries: Weak<WriterDeliveries>,
    id: String,
}

impl Drop for DeliveryLease {
    fn drop(&mut self) {
        if let Some(deliveries) = self.deliveries.upgrade() {
            deliveries.0.lock().remove(&self.id);
        }
    }
}

pub(crate) struct RequestWriter {
    session: Weak<ClientSession>,
    writer_id: u64,
    deliveries: Arc<WriterDeliveries>,
    receiver: mpsc::Receiver<QueuedRequest>,
}

impl RequestWriter {
    pub(crate) async fn recv(&mut self) -> Option<QueuedRequest> {
        self.receiver.recv().await
    }

    pub(crate) fn try_recv(&mut self) -> Result<QueuedRequest, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }

    pub(crate) fn queued_count(&self) -> usize {
        self.receiver.len()
    }
}

impl Drop for RequestWriter {
    fn drop(&mut self) {
        if let Some(session) = self.session.upgrade() {
            session
                .request_writers
                .0
                .lock()
                .writers
                .remove(&self.writer_id);
        }
        self.deliveries.fail_all();
    }
}
