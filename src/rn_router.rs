use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::net::TcpStream;
use tokio::sync::mpsc;

use std::io::ErrorKind;

use tokio::net::TcpListener;
use tokio::io::split;

use std::os::unix::io::AsRawFd;

use crate::{
    SmppPdu,
    OperatorConfig,
    CMD_BIND_TRANSCEIVER, CMD_BIND_TRANSCEIVER_RESP,
    CMD_ENQUIRE_LINK, CMD_ENQUIRE_LINK_RESP,
    CMD_SUBMIT_SM, CMD_SUBMIT_SM_RESP,
    CMD_UNBIND, CMD_UNBIND_RESP,
    CMD_DATA_SM,
    ESME_ROK,
    SEQUENCE_COUNTER,
    FRAGMENT_SEQUENCES,
    register_fragment_sequence,
    is_fragment_sequence,
};

/// Configuración del Router RN tal como se deserializa desde config.yaml
#[derive(Debug, serde::Deserialize, Clone)]
pub struct RouterConfig {
    pub name: String,
    pub listen_port: u16,
    pub system_id: String,
    pub password: String,
    pub routing_rules: HashMap<String, String>,     // "20" -> "Claro"
    #[serde(default)]
    pub rn_origin_expected: Option<String>,         // p.ej. "61"
    #[serde(default = "default_strip_rn")]
    pub strip_rn_on_forward: bool,                  // true => quita RN al reenviar
}

fn default_strip_rn() -> bool { true }

#[derive(Debug, Clone)]
struct RnConfig {
    rn_map: HashMap<String, String>,       // "20" -> "Operador"
    rn_origin_expected: Option<String>,    // Some("61") o None
    strip_rn_on_forward: bool,
}

#[derive(Debug)]
enum RnParseError {
    TooShort,
    NonDigit,
    BadOrigin(String),
    UnknownOperator(String),
}

/// Analiza el destino con formato [RN_op(2)][RN_origen(2)]9XXXXXXXX (13 dígitos)
/// Devuelve (operator_name, forward_addr) según rn_map y strip_rn_on_forward.
fn route_for_dest(dest_addr: &str, cfg: &RnConfig) -> Result<(String, String), RnParseError> {
    let s = dest_addr.trim();
    if s.len() < 13 { return Err(RnParseError::TooShort); }
    if !s.chars().all(|c| c.is_ascii_digit()) { return Err(RnParseError::NonDigit); }
    let rn_op = &s[0..2];
    let rn_origin = &s[2..4];
    let rest = &s[4..];

    if let Some(exp) = &cfg.rn_origin_expected {
        if rn_origin != exp {
            return Err(RnParseError::BadOrigin(rn_origin.to_string()));
        }
    }
    let op_name = cfg.rn_map.get(rn_op)
        .cloned()
        .ok_or_else(|| RnParseError::UnknownOperator(rn_op.to_string()))?;

    let forward_addr = if cfg.strip_rn_on_forward {
        rest.to_string()
    } else {
        s.to_string()
    };
    Ok((op_name, forward_addr))
}

/// Extrae destination_addr (C-Octet String) del body de un SUBMIT_SM.
/// No depende de otros helpers del main.
fn extract_destination_addr(body: &[u8]) -> Result<(usize, usize, String), &'static str> {
    // Recorremos campos fijos: service_type\0, src TON+NPI (2), src addr\0, dst TON+NPI (2), dst addr\0
    let mut pos = 0usize;

    // service_type
    while pos < body.len() && body[pos] != 0 { pos += 1; }
    if pos >= body.len() { return Err("bad service_type"); }
    pos += 1; // null

    // source TON/NPI
    if pos + 2 > body.len() { return Err("bad src ton/npi"); }
    pos += 2;

    // source addr c-octet
    while pos < body.len() && body[pos] != 0 { pos += 1; }
    if pos >= body.len() { return Err("bad src addr"); }
    pos += 1; // null

    // dest TON/NPI
    if pos + 2 > body.len() { return Err("bad dst ton/npi"); }
    pos += 2;

    // dest addr start
    let start_dst = pos;
    while pos < body.len() && body[pos] != 0 { pos += 1; }
    if pos >= body.len() { return Err("bad dst addr"); }
    let end_dst_null = pos; // posición del byte 0 de terminación

    let dest = String::from_utf8_lossy(&body[start_dst..end_dst_null]).to_string();
    Ok((start_dst, end_dst_null, dest))
}

/// Reescribe in-place el destination_addr en el body de SUBMIT_SM (C-Octet String).
fn rewrite_destination_addr(body: &mut Vec<u8>, new_dest: &str) -> Result<(), &'static str> {
    let (start_dst, end_dst_null, _old) = extract_destination_addr(body)?;
    let mut out = Vec::with_capacity(body.len() + new_dest.len() + 1);
    out.extend_from_slice(&body[..start_dst]);
    out.extend_from_slice(new_dest.as_bytes());
    out.push(0u8);
    if end_dst_null + 1 <= body.len() {
        out.extend_from_slice(&body[end_dst_null + 1..]);
    }
    *body = out;
    Ok(())
}

/// Construye el body de BIND_TRANSCEIVER 3.4 mínimo
fn build_bind_trx_body(system_id: &str, password: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(system_id.as_bytes()); b.push(0);
    b.extend_from_slice(password.as_bytes());  b.push(0);
    b.push(0);     // system_type ""
    b.push(0x34);  // interface_version 3.4
    b.push(0);     // addr_ton
    b.push(0);     // addr_npi
    b.push(0);     // address_range ""
    b
}

/// Conexión saliente del router hacia un SMSC (por operador).
/// Recibe PDUs desde el router (rx_from_router) y escribe al SMSC.
/// Las respuestas del SMSC se reenvían a tx_to_router_resp junto al sequence_number.
async fn smsc_task(
    op: OperatorConfig,
    mut rx_from_router: mpsc::Receiver<SmppPdu>,
    tx_to_router_resp: mpsc::Sender<(u32, SmppPdu)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut smsc = TcpStream::connect((op.smsc_host.as_str(), op.smsc_port)).await?;
    unsafe {
        let fd = smsc.as_raw_fd();
        let val: libc::c_int = 1;
        if libc::setsockopt(
            fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        ) != 0 {
            eprintln!("Error setting keepalive for SMSC {}: {}", op.name, std::io::Error::last_os_error());
        }
    }

    // BIND_TRX al SMSC como cliente
    let bind_body = build_bind_trx_body(&op.system_id, &op.password);
    let bind_pdu = SmppPdu::new_with_next_seq(CMD_BIND_TRANSCEIVER, ESME_ROK, bind_body);
    bind_pdu.write_to(&mut smsc).await?; // Usar smsc directamente
    let bind_resp = SmppPdu::read_from(&mut smsc).await?; // Usar smsc directamente

    bind_resp.log();
    if bind_resp.command_id != CMD_BIND_TRANSCEIVER_RESP || bind_resp.command_status != ESME_ROK {
        return Err("Bind to SMSC failed".into());
    }
    println!("[Router->{}] bound successfully", op.name);

    // AHORA hacer el split() después del BIND
    let (mut sr, mut sw) = split(smsc);

    // Writer hacia SMSC
    let writer = tokio::spawn(async move {
        while let Some(pdu) = rx_from_router.recv().await {
            if pdu.write_to(&mut sw).await.is_err() { break; }
        }
    });

    // Reader desde SMSC
    let reader = {
        let tx_resp = tx_to_router_resp.clone();
        tokio::spawn(async move {
            loop {
                match SmppPdu::read_from(&mut sr).await {
                    Ok(pdu) => {
                        pdu.log();
                        if tx_resp.send((pdu.sequence_number, pdu)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                    Err(e) => { eprintln!("[Router->{}] SMSC read error: {}", op.name, e); break; }
                }
            }
        })
    };

    let (_r, _w) = tokio::join!(reader, writer);
    Ok(())
}

/// Inicia el servidor SMPP del Router RN en `router.listen_port`.
/// Levanta conexiones/binds a los SMSC definidos en `routing_rules`.
pub async fn run_rn_router(
    router: RouterConfig,
    operators: Vec<OperatorConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Armar config RN
    let rn_cfg = RnConfig {
        rn_map: router.routing_rules.clone(),
        rn_origin_expected: router.rn_origin_expected.clone(),
        strip_rn_on_forward: router.strip_rn_on_forward,
    };

    // Canales por operador: para enviar PDUs hacia su SMSC
    let mut out_tx: HashMap<String, mpsc::Sender<SmppPdu>> = HashMap::new();
    // Canal común para recolectar respuestas de cualquier SMSC
    let (tx_resp, mut rx_resp) = mpsc::channel::<(u32, SmppPdu)>(512);

    for (rn, op_name) in rn_cfg.rn_map.iter() {
        if let Some(opcfg) = operators.iter().find(|o| o.name == *op_name).cloned() {
            let (tx, rx) = mpsc::channel::<SmppPdu>(512);
            out_tx.insert(opcfg.name.clone(), tx);
            let tx_resp_clone = tx_resp.clone();
        
            // Clonar op_name ANTES de mover al closure
            let op_name_owned = op_name.clone();
        
            tokio::spawn(async move {
                if let Err(e) = smsc_task(opcfg, rx, tx_resp_clone).await {
                    eprintln!("[Router] SMSC {} error: {}", op_name_owned, e);
                }
            });
        } else {
            eprintln!("[Router] WARNING: RN {} mapea a operador '{}' que no está en 'operators'", rn, op_name);
        }
    }

    // Mapa global de correlación: seq_enviado_al_SMSC -> (tx_al_cliente, seq_del_cliente)
    let seq_map: Arc<Mutex<HashMap<u32, (mpsc::Sender<SmppPdu>, u32)>>> = Arc::new(Mutex::new(HashMap::new()));
    let seq_map_reader = seq_map.clone();

    // Tarea: respuestas desde SMSC → al cliente correcto
    tokio::spawn(async move {
        while let Some((seq_from_smsc, mut pdu)) = rx_resp.recv().await {
            // Suprimir respuestas de fragmentos generados por nosotros (si existiera ese caso)
            if is_fragment_sequence(seq_from_smsc) {
                FRAGMENT_SEQUENCES.write().unwrap().remove(&seq_from_smsc);
                continue;
            }
        
            // CORRECCIÓN: Separar la obtención del MutexGuard del await
            let client_info = {
                let mut seq_map = seq_map_reader.lock().unwrap();
                seq_map.remove(&seq_from_smsc)
            }; // El MutexGuard se libera aquí

            if let Some((tx_client, client_seq)) = client_info {
                // reescribir seq para el cliente
                pdu.sequence_number = client_seq;
                let _ = tx_client.send(pdu).await; // OK: lock ya liberado
            } else {
                // Respuesta no mapeada; ignorar o loguear
            }
        }
    });

    // Listener del Router RN
    let listener = TcpListener::bind(("0.0.0.0", router.listen_port)).await?;
    println!("→ [Router:{}] Listening on port {}", router.name, router.listen_port);

    loop {
        let (mut client, addr) = listener.accept().await?;
        let rn_cfg = rn_cfg.clone();
        let out_tx_map = out_tx.clone();
        let seq_map_conn = seq_map.clone();
        let router_system_id = router.system_id.clone();

        tokio::spawn(async move {
            // Aceptar BIND del cliente y responder localmente
            let bind_req = match SmppPdu::read_from(&mut client).await {
                Ok(p) => p,
                Err(e) => { eprintln!("[Router] bind read error: {}", e); return; }
            };
            bind_req.log();
            if bind_req.command_id != CMD_BIND_TRANSCEIVER {
                eprintln!("[Router] First PDU is not BIND_TRX from {}", addr);
                return;
            }
            let mut body = Vec::new();
            body.extend_from_slice(router_system_id.as_bytes());
            body.push(0); // Null terminator for C-Octet string
            let bind_resp = bind_req.new_response(CMD_BIND_TRANSCEIVER_RESP, ESME_ROK, body);
            if let Err(e) = bind_resp.write_to(&mut client).await {
                eprintln!("[Router] bind_resp write error: {}", e);
                return;
            }
            println!("[Router] bound client {}", addr);

            let (mut cr, mut cw) = split(client);
            // Canal para enviar PDUs de vuelta a este cliente
            let (tx_client, mut rx_to_client) = mpsc::channel::<SmppPdu>(512);

            // Writer hacia cliente
            let w_client = tokio::spawn(async move {
                while let Some(pdu) = rx_to_client.recv().await {
                    if pdu.write_to(&mut cw).await.is_err() { break; }
                }
            });

            // Reader desde cliente
            let r_client = tokio::spawn(async move {
                loop {
                    match SmppPdu::read_from(&mut cr).await {
                        Ok(mut pdu) => {
                            pdu.log();
                            match pdu.command_id {
                                CMD_UNBIND => {
                                    let resp = pdu.new_response(CMD_UNBIND_RESP, ESME_ROK, Vec::new());
                                    let _ = tx_client.send(resp).await;
                                    break;
                                }
                                CMD_ENQUIRE_LINK => {
                                    let resp = pdu.new_response(CMD_ENQUIRE_LINK_RESP, ESME_ROK, Vec::new());
                                    let _ = tx_client.send(resp).await;
                                }
                                CMD_SUBMIT_SM | CMD_DATA_SM => {
                                    // Extraer destino actual
                                    let dst = match extract_destination_addr(&pdu.body) {
                                        Ok((_s, _e, d)) => d,
                                        Err(_) => {
                                            // ESME_RINVDSTADR
                                            let resp = pdu.new_response(pdu.get_response_id(), 0x0000000B, Vec::new());
                                            let _ = tx_client.send(resp).await;
                                            continue;
                                        }
                                    };
                                    // Ruteo RN -> operador
                                    let (op_name, forward_addr) = match route_for_dest(&dst, &rn_cfg) {
                                        Ok(v) => v,
                                        Err(err) => {
                                            eprintln!("[Router] RN parse error for {}: {:?}", dst, err);
                                            let resp = pdu.new_response(pdu.get_response_id(), 0x0000000B, Vec::new());
                                            let _ = tx_client.send(resp).await;
                                            continue;
                                        }
                                    };
                                    // Reescribir destino si corresponde
                                    let mut forward_pdu = pdu.clone();
                                    if let Err(e) = rewrite_destination_addr(&mut forward_pdu.body, &forward_addr) {
                                        eprintln!("[Router] rewrite dest error: {}", e);
                                        let resp = pdu.new_response(pdu.get_response_id(), 0x0000000B, Vec::new());
                                        let _ = tx_client.send(resp).await;
                                        continue;
                                    }
                                    forward_pdu.command_length = 16 + forward_pdu.body.len() as u32;

                                    // Enviar al SMSC del operador con nueva secuencia y mapear respuesta
                                    if let Some(tx_smsc) = out_tx_map.get(&op_name) {
                                        let new_seq = SEQUENCE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                        seq_map_conn.lock().unwrap().insert(new_seq, (tx_client.clone(), pdu.sequence_number));
                                        forward_pdu.sequence_number = new_seq;

                                        if tx_smsc.send(forward_pdu).await.is_err() {
                                            eprintln!("[Router] send submit to SMSC {} failed", op_name);
                                            seq_map_conn.lock().unwrap().remove(&new_seq);
                                            let resp = pdu.new_response(pdu.get_response_id(), 0x00000008, Vec::new()); // ESME_RSYSERR
                                            let _ = tx_client.send(resp).await;
                                        }
                                    } else {
                                        eprintln!("[Router] operator '{}' has no active SMSC tx", op_name);
                                        let resp = pdu.new_response(pdu.get_response_id(), 0x00000008, Vec::new());
                                        let _ = tx_client.send(resp).await;
                                    }
                                }
                                _ => {
                                    // Otros tipos: puedes implementar según necesidad (DATA_SM, etc.)
                                }
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                        Err(e) => { eprintln!("[Router] client read error: {}", e); break; }
                    }
                }
            });

            let (_r, _w) = tokio::join!(r_client, w_client);
            println!("[Router] client {} disconnected", addr);
        });
    }
}

