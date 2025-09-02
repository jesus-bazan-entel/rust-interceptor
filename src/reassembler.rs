use tokio::{
    sync::mpsc::{Sender, UnboundedSender, unbounded_channel},
    time::{Instant, Duration, interval},
};
use std::collections::HashMap;
use crate::SmppPdu;
use crate::{CMD_SUBMIT_SM, ESME_ROK};
use tracing::info;

/// Datos de un fragmento extraído
#[derive(Debug)]
pub struct Fragment {
    pub message_id:      u32,
    pub total_parts:     u8,
    pub part_number:     u8,
    pub prefix:          Vec<u8>, // bytes SMPP body antes de sm_length
    pub content:         Vec<u8>, // UDH + datos
    pub data_coding:     u8,
    pub esm_class:       u8,
    pub sequence_number: u32,
}

/// Crea el actor reensamblador que usa tx2smsc para reenviar mensajes completos
pub fn spawn_reassembler_with_sender(
    expiry_secs: u64,
    tx2smsc: Sender<SmppPdu>,
    operator: String,
) -> UnboundedSender<Fragment> {
    let (tx, mut rx) = unbounded_channel::<Fragment>();

    tokio::spawn(async move {
        struct State {
            prefix:      Vec<u8>,
            parts:       Vec<Option<Vec<u8>>>,
            timestamp:   Instant,
            data_coding: u8,
            esm_class:   u8,
        }

        let mut buffer: HashMap<u32, State> = HashMap::new();
        let mut cleaner = interval(Duration::from_secs(expiry_secs));

        loop {
            tokio::select! {
                Some(fr) = rx.recv() => {
                    let state = buffer.entry(fr.message_id).or_insert_with(|| {
                        State {
                            prefix: fr.prefix.clone(),
                            parts: vec![None; fr.total_parts as usize],
                            timestamp: Instant::now(),
                            data_coding: fr.data_coding,
                            esm_class: fr.esm_class,
                        }
                    });

                    state.parts[(fr.part_number - 1) as usize] = Some(fr.content.clone());
                    state.timestamp = Instant::now();

                    if state.parts.iter().all(|o| o.is_some()) {
                        // Concatenar
                        let mut full = Vec::new();
                        for seg in state.parts.iter() {
                            full.extend(seg.as_ref().unwrap());
                        }
                        info!("[{}] Reassembled message ID={:08X}", operator, fr.message_id);

                        // Reconstruir body SMPP
                        let mut body = state.prefix.clone();
                        body.push(full.len() as u8);
                        body.extend_from_slice(&full);

                        // Nuevo PDU completo
                        let pdu = SmppPdu::new(
                            CMD_SUBMIT_SM,
                            ESME_ROK,
                            fr.sequence_number,
                            body
                        );
                        let _ = tx2smsc.send(pdu);
                        buffer.remove(&fr.message_id);
                    }
                }

                _ = cleaner.tick() => {
                    let now = Instant::now();
                    let expired: Vec<u32> = buffer.iter()
                        .filter(|(_, st)| now.duration_since(st.timestamp) > Duration::from_secs(expiry_secs))
                        .map(|(id, _)| *id)
                        .collect();
                    for id in expired {
                        info!("[{}] Expired message ID={:08X}", operator, id);
                        buffer.remove(&id);
                    }
                }
            }
        }
    });

    tx
}
