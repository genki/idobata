use crate::{
    crypto,
    error::{NETWORK, Result},
    scanner::Scanner,
    types::{Config, TrustedRoom},
    util,
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    PeerId, StreamProtocol, Swarm, SwarmBuilder, allow_block_list, connection_limits, identity,
    noise,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    tcp, yamux,
};
use std::{collections::BTreeSet, io, time::Duration};

/// Knowledge records carry historical authorization and signed review evidence.
/// Keep this independent of the compact legacy message frames and local IPC.
pub const MAX_KNOWLEDGE_WIRE: usize = 4 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct Codec;
async fn read<T: AsyncRead + Unpin>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    io.read_exact(&mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > max {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0u8; len];
    io.read_exact(&mut bytes).await?;
    let mut trailing = [0u8; 1];
    if io.read(&mut trailing).await? != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}
async fn write<T: AsyncWrite + Unpin>(io: &mut T, data: Vec<u8>, max: usize) -> io::Result<()> {
    if data.is_empty() || data.len() > max {
        return Err(io::ErrorKind::InvalidData.into());
    }
    io.write_all(&(data.len() as u32).to_be_bytes()).await?;
    io.write_all(&data).await?;
    io.close().await
}
impl request_response::Codec for Codec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Vec<u8>> {
        read(io, 16384).await
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Vec<u8>> {
        read(io, 4096).await
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        data: Vec<u8>,
    ) -> io::Result<()> {
        write(io, data, 16384).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        data: Vec<u8>,
    ) -> io::Result<()> {
        write(io, data, 4096).await
    }
}
#[derive(Clone, Default)]
pub struct KnowledgeCodec;
impl request_response::Codec for KnowledgeCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Vec<u8>> {
        read(io, MAX_KNOWLEDGE_WIRE).await
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Vec<u8>> {
        read(io, MAX_KNOWLEDGE_WIRE).await
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        data: Vec<u8>,
    ) -> io::Result<()> {
        write(io, data, MAX_KNOWLEDGE_WIRE).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        data: Vec<u8>,
    ) -> io::Result<()> {
        write(io, data, MAX_KNOWLEDGE_WIRE).await
    }
}
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub messages: request_response::Behaviour<Codec>,
    pub knowledge: request_response::Behaviour<KnowledgeCodec>,
    pub allowed: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    pub limits: connection_limits::Behaviour,
}
pub async fn build(key: identity::Keypair, c: &Config) -> Result<Swarm<Behaviour>> {
    let messages = request_response::Behaviour::with_codec(
        Codec,
        [(
            StreamProtocol::new("/idobata/message/2"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default()
            .with_request_timeout(Duration::from_secs(5))
            .with_max_concurrent_streams(8),
    );
    let limits = connection_limits::ConnectionLimits::default()
        .with_max_pending_incoming(Some(8))
        .with_max_pending_outgoing(Some(8))
        .with_max_established(Some(8))
        .with_max_established_per_peer(Some(1));
    let knowledge = request_response::Behaviour::with_codec(
        KnowledgeCodec,
        [(
            StreamProtocol::new("/idobata/knowledge/1"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default()
            // Background replicas can include a complete signed review bundle.
            // Interactive queries keep their own shorter deadline in Runtime.
            .with_request_timeout(Duration::from_secs(15))
            .with_max_concurrent_streams(8),
    );
    let behaviour = Behaviour {
        messages,
        knowledge,
        allowed: Default::default(),
        limits: connection_limits::Behaviour::new(limits),
    };
    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|_| NETWORK)?
        .with_dns()
        .map_err(|_| NETWORK)?
        .with_websocket(noise::Config::new, yamux::Config::default)
        .await
        .map_err(|_| NETWORK)?
        .with_behaviour(|_| behaviour)
        .map_err(|_| NETWORK)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    for addr in &c.listen {
        swarm
            .listen_on(crypto::address(addr, true)?)
            .map_err(|_| NETWORK)?;
    }
    Ok(swarm)
}
pub fn refresh(
    swarm: &mut Swarm<Behaviour>,
    c: &Config,
    previous: &mut BTreeSet<PeerId>,
    own: &str,
) {
    let mut current = BTreeSet::new();
    for room in c.rooms.values() {
        if crypto::validate_room(room, &Scanner::policy_id(), util::now()).is_err()
            || !room
                .certificate
                .signed
                .members
                .iter()
                .any(|m| m.peer_id == own)
        {
            continue;
        }
        for m in &room.certificate.signed.members {
            if m.peer_id == own {
                continue;
            }
            if let Ok(peer) = m.peer_id.parse::<PeerId>() {
                current.insert(peer);
                swarm.behaviour_mut().allowed.allow_peer(peer);
                for a in &m.addresses {
                    if let Ok(addr) = crypto::address(a, false) {
                        swarm.add_peer_address(peer, addr);
                    }
                }
            }
        }
    }
    for peer in previous.difference(&current) {
        swarm.behaviour_mut().allowed.disallow_peer(*peer);
        let _ = swarm.disconnect_peer_id(*peer);
    }
    *previous = current;
}
pub fn room_for<'a>(c: &'a Config, id: &str, own: &str) -> Option<&'a TrustedRoom> {
    c.rooms.values().find(|r| {
        r.certificate.signed.room_id == id
            && r.certificate
                .signed
                .members
                .iter()
                .any(|m| m.peer_id == own)
            && crypto::validate_room(r, &Scanner::policy_id(), util::now()).is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, io::Cursor};
    use libp2p::request_response::Codec as _;

    fn frame(bytes: &[u8]) -> Cursor<Vec<u8>> {
        let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(bytes);
        Cursor::new(frame)
    }

    #[test]
    fn knowledge_frames_accept_full_evidence_bundles_up_to_four_mib() {
        block_on(async {
            let protocol = StreamProtocol::new("/idobata/knowledge/1");
            let data = vec![b'x'; MAX_KNOWLEDGE_WIRE];
            let mut codec = KnowledgeCodec;
            let mut output = Cursor::new(Vec::new());
            codec
                .write_request(&protocol, &mut output, data.clone())
                .await
                .unwrap();
            output.set_position(0);
            assert_eq!(
                codec.read_request(&protocol, &mut output).await.unwrap(),
                data
            );

            let mut output = Cursor::new(Vec::new());
            codec
                .write_response(&protocol, &mut output, data.clone())
                .await
                .unwrap();
            output.set_position(0);
            assert_eq!(
                codec.read_response(&protocol, &mut output).await.unwrap(),
                data
            );
        });
    }

    #[test]
    fn knowledge_rejects_empty_oversized_truncated_and_trailing_frames() {
        block_on(async {
            let protocol = StreamProtocol::new("/idobata/knowledge/1");
            let mut codec = KnowledgeCodec;
            for length in [0, MAX_KNOWLEDGE_WIRE + 1] {
                let mut prefix = Cursor::new((length as u32).to_be_bytes().to_vec());
                assert!(codec.read_request(&protocol, &mut prefix).await.is_err());
                let mut prefix = Cursor::new((length as u32).to_be_bytes().to_vec());
                assert!(codec.read_response(&protocol, &mut prefix).await.is_err());
                let data = vec![0; length];
                let mut output = Cursor::new(Vec::new());
                assert!(
                    codec
                        .write_request(&protocol, &mut output, data.clone())
                        .await
                        .is_err()
                );
                assert!(output.into_inner().is_empty());
                let mut output = Cursor::new(Vec::new());
                assert!(
                    codec
                        .write_response(&protocol, &mut output, data)
                        .await
                        .is_err()
                );
                assert!(output.into_inner().is_empty());
            }
            let mut truncated = frame(b"payload");
            truncated.get_mut().pop();
            assert!(codec.read_request(&protocol, &mut truncated).await.is_err());
            let mut trailing = frame(b"payload");
            trailing.get_mut().push(b'x');
            assert!(codec.read_response(&protocol, &mut trailing).await.is_err());
        });
    }

    #[test]
    fn legacy_message_frame_limits_remain_independent() {
        block_on(async {
            let protocol = StreamProtocol::new("/idobata/message/2");
            let mut codec = Codec;
            assert_eq!(
                codec
                    .read_request(&protocol, &mut frame(&vec![0; 16_384]))
                    .await
                    .unwrap()
                    .len(),
                16_384
            );
            assert!(
                codec
                    .read_request(&protocol, &mut frame(&vec![0; 16_385]))
                    .await
                    .is_err()
            );
            assert_eq!(
                codec
                    .read_response(&protocol, &mut frame(&vec![0; 4_096]))
                    .await
                    .unwrap()
                    .len(),
                4_096
            );
            assert!(
                codec
                    .read_response(&protocol, &mut frame(&vec![0; 4_097]))
                    .await
                    .is_err()
            );
        });
    }
}
