use std::{collections::HashSet, str::FromStr, sync::LazyLock, time::Duration};

use async_trait::async_trait;
use quinn::{Connection, ConnectionError, ReadError, RecvStream};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use tokio::{sync::RwLock, task, time::timeout};

use crate::{protocol::p2p_auth::PeerId, sync::SyncError};

use super::{Event, EventStream};

const STREAM_BUFFER_SIZE: usize = 4096; // Arbitrary 4k buffer size might change later as needed
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
/// This is a map of the peer ids of all the peers we are currently streaming from this is used to
/// make sure we don't duplicate streams
static PEER_STREAMS_MAP: LazyLock<RwLock<HashSet<PeerId>>> =
   LazyLock::new(|| RwLock::new(HashSet::new()));

#[derive(Error, Debug)]
pub enum PeerStreamError {
   #[error("Failed to open peer event stream")]
   FailedToOpenStream(#[from] ConnectionError),
   #[error("Invalid peer event stream data")]
   InvalidEventPacket(#[from] postcard::Error),
   #[error("Failed to read peer event stream")]
   FailedToReadStream(#[from] ReadError),
   #[error("Took too long to accpet peer event stream")]
   TookTooLong,
}
impl SyncError for PeerStreamError {}

// -- PeerId Deserialize --

/// Deserializes a PeerId from a hex string
fn deserialize_peer_id<'de, D>(deserializer: D) -> Result<PeerId, D::Error>
where
   D: Deserializer<'de>,
{
   let s = String::deserialize(deserializer)?;
   PeerId::from_str(&s).map_err(de::Error::custom)
}

/// Serializes a PeerId to a hex string
fn serialize_peer_id<S>(peer_id: &PeerId, serializer: S) -> Result<S::Ok, S::Error>
where
   S: Serializer,
{
   let s = peer_id.to_string();
   serializer.serialize_str(&s)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PeerEvent {
   #[serde(
      deserialize_with = "deserialize_peer_id",
      serialize_with = "serialize_peer_id"
   )]
   peer_id: PeerId,
   event: Event,
}

pub struct PeerEventStream {
   stream: RecvStream,

   // we can make this a heap dynamically allocated buffer later if we need to
   buffer: [u8; STREAM_BUFFER_SIZE],

   peer_id: PeerId,
}

impl PeerEventStream {
   pub async fn accept(
      connection: &mut Connection, peer_id: PeerId,
   ) -> Result<Self, PeerStreamError> {
      use PeerStreamError::TookTooLong;

      let stream = timeout(ACCEPT_TIMEOUT, connection.accept_uni())
         .await
         .map_err(|_| TookTooLong)??;

      assert!(
         !PEER_STREAMS_MAP.read().await.contains(&peer_id),
         "We are already streaming events from this peer"
      );

      PEER_STREAMS_MAP.write().await.insert(peer_id);
      Ok(Self {
         stream,
         buffer: [0; STREAM_BUFFER_SIZE],
         peer_id: peer_id,
      })
   }
}

impl Drop for PeerEventStream {
   fn drop(&mut self) {
      let peer_id = self.peer_id;
      task::spawn(async move {
         PEER_STREAMS_MAP.write().await.remove(&peer_id);
      });
   }
}

#[async_trait]
impl EventStream<PeerStreamError> for PeerEventStream {
   async fn next(&mut self) -> Result<Option<Event>, PeerStreamError> {
      loop {
         let read = self
            .stream
            .read(&mut self.buffer)
            .await?
            .unwrap_or_default();

         let closed = read == 0;
         if closed {
            return Ok(None);
         }

         let event = postcard::from_bytes::<PeerEvent>(&self.buffer[..read])?;
         self.buffer[..read].fill(0);

         let duplicated =
            PEER_STREAMS_MAP.read().await.contains(&event.peer_id) && event.peer_id != self.peer_id;

         if duplicated {
            continue;
         }

         return Ok(Some(event.event));
      }
   }
}
