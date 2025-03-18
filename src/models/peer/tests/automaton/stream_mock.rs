use crate::{connect_to_peers::get_codec_rules, models::peer::PeerMessage};
use tokio::io::DuplexStream;
use tokio_serde::{
    formats::{Bincode, SymmetricalBincode},
    SymmetricallyFramed,
};
use tokio_util::codec::Framed;
use tokio_util::codec::LengthDelimitedCodec;

pub type PeerMessageSocket = SymmetricallyFramed<
    Framed<
        // ReadHalf<
        DuplexStream, // >
        LengthDelimitedCodec,
    >,
    PeerMessage,
    Bincode<PeerMessage, PeerMessage>,
>;

pub(super) fn create_peer_message_duplex() -> (PeerMessageSocket, PeerMessageSocket) {
    let (left, right) = tokio::io::duplex(2u32.pow(19) as usize);
    // let (client_read, client_write) =
    //     tokio::io::split(client);
    // let (server_read, server_write) =
    //     tokio::io::split(server);

    (
        SymmetricallyFramed::new(
            Framed::new(left, get_codec_rules()),
            SymmetricalBincode::default(),
        ),
        SymmetricallyFramed::new(
            Framed::new(right, get_codec_rules()),
            SymmetricalBincode::default(),
        ),
    )
}
