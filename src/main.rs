use std::{
    collections::{HashMap, HashSet},
    io::ErrorKind,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock, LazyLock, atomic::{AtomicU32, Ordering}},
    time::Duration,
    os::unix::io::AsRawFd,
    fs,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use serde::Deserialize;

mod sms_fragment;
use sms_fragment::{SharedSmsBuffer, process_udh};

mod multi_buffer;
use multi_buffer::setup_multi_buffer_system;

// ----- SMPP constants -----
const CMD_BIND_TRANSCEIVER:      u32 = 0x00000009;
const CMD_BIND_TRANSCEIVER_RESP: u32 = 0x80000009;
const CMD_ENQUIRE_LINK:          u32 = 0x00000015;
const CMD_ENQUIRE_LINK_RESP:     u32 = 0x80000015;
const CMD_SUBMIT_SM:             u32 = 0x00000004;
const CMD_SUBMIT_SM_RESP:        u32 = 0x80000004;
const CMD_DELIVER_SM:            u32 = 0x00000005;
const CMD_DELIVER_SM_RESP:       u32 = 0x80000005;
const CMD_UNBIND:                u32 = 0x00000006;
const CMD_UNBIND_RESP:           u32 = 0x80000006;
const CMD_DATA_SM:               u32 = 0x00000103;
const CMD_DATA_SM_RESP:          u32 = 0x80000103;
const ESME_ROK:                  u32 = 0x00000000;

// Contador de secuencia global para PDUs generados
static SEQUENCE_COUNTER: AtomicU32 = AtomicU32::new(1);

// Una estructura global para rastrear sequence_numbers de fragmentos
static FRAGMENT_SEQUENCES: LazyLock<RwLock<HashSet<u32>>> = LazyLock::new(|| RwLock::new(HashSet::new()));

// Función para verificar si un sequence_number pertenece a un fragmento
fn is_fragment_sequence(seq: u32) -> bool {
    FRAGMENT_SEQUENCES.read().unwrap().contains(&seq)
}

// Función para registrar un sequence_number como perteneciente a un fragmento
fn register_fragment_sequence(seq: u32) {
    FRAGMENT_SEQUENCES.write().unwrap().insert(seq);
}

#[derive(Debug, Deserialize, Clone)]
struct AppConfig {
    operators: Vec<OperatorConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct OperatorConfig {
    name: String,
    listen_port: u16,
    smsc_host: String,
    smsc_port: u16,
    system_id: String,
    password: String,
}

struct SmppInterceptor {
    cfg: OperatorConfig,
    sessions: Arc<Mutex<HashMap<String, SocketAddr>>>,
    buffer: SharedSmsBuffer,
}

#[derive(Clone, Debug)]
struct SmppPdu {
    command_length: u32,
    command_id: u32,
    command_status: u32,
    sequence_number: u32,
    body: Vec<u8>,
}

impl SmppInterceptor {
    fn new(cfg: OperatorConfig) -> Self {
        let _ = setup_multi_buffer_system();
        Self {
            cfg,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            buffer: SharedSmsBuffer::new(300),
        }
    }

    async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(("0.0.0.0", self.cfg.listen_port)).await?;
        println!("→ [{}] Listening on port {}", self.cfg.name, self.cfg.listen_port);

        loop {
            let (stream, addr) = match listener.accept().await {
                Ok((s, a)) => (s, a),
                Err(e) => {
                    eprintln!("Error aceptando conexión: {}", e);
                    continue;
                }
            };
        
            let sessions = self.sessions.clone();
            let buffer = self.buffer.clone();
            let config = self.cfg.clone();
            
            tokio::spawn(async move {
                let config_clone = config.clone(); // Clon para el error
                
                if let Err(e) = handle_connection(
                    stream, 
                    addr, 
                    config, // Se mueve aquí
                    sessions, 
                    buffer
                ).await {
                    eprintln!("[{}] Error: {}", config_clone.name, e);
                }
            });
        }
    }
}

impl SmppPdu {
    fn new(cmd: u32, status: u32, seq: u32, body: Vec<u8>) -> Self {
        Self {
            command_length: 16 + body.len() as u32,
            command_id: cmd,
            command_status: status,
            sequence_number: seq,
            body,
        }
    }

    fn new_with_next_seq(cmd: u32, status: u32, body: Vec<u8>) -> Self {
        let seq = SEQUENCE_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self::new(cmd, status, seq, body)
    }

    fn new_response(&self, cmd_id: u32, status: u32, body: Vec<u8>) -> Self {
        Self::new(cmd_id, status, self.sequence_number, body)
    }

    async fn read_from<T: AsyncReadExt + Unpin>(stream: &mut T) -> Result<Self, std::io::Error> {
        let mut hdr = [0u8; 16];
        stream.read_exact(&mut hdr).await?;
        let command_length = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
        let command_id = u32::from_be_bytes(hdr[4..8].try_into().unwrap());
        let command_status = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
        let sequence_number = u32::from_be_bytes(hdr[12..16].try_into().unwrap());



        //  ────────── FILTROS ADICIONALES ──────────
        // 1) length 0 ya lo tenías…
        if command_length == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "zero‐length PDU",
            ));
        }
        // 2) si llegara un PDU sin cuerpo (len==16) _y_ es el "0|response" a un cmd 0, lo descartamos:
        if command_length == 16 && (command_id & 0x7FFF_FFFF) == 0 && sequence_number == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "spurious zero‐response PDU",
            ));
        }
        if command_length < 16 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "PDU length < 16",
            ));
        }

              
        let body_len = (command_length - 16) as usize;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            stream.read_exact(&mut body).await?;
        }
        Ok(SmppPdu {
            command_length,
            command_id,
            command_status,
            sequence_number,
            body,
        })
    }

    async fn write_to<T: AsyncWriteExt + Unpin>(&self, stream: &mut T) -> Result<(), std::io::Error> {
        let mut buf = Vec::with_capacity(self.command_length as usize);
        buf.extend_from_slice(&self.command_length.to_be_bytes());
        buf.extend_from_slice(&self.command_id.to_be_bytes());
        buf.extend_from_slice(&self.command_status.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.body);
        stream.write_all(&buf).await
    }

    fn log(&self) {
        println!(
            "▶ PDU cmd=0x{:08X} seq={} len={}",
            self.command_id, self.sequence_number, self.command_length
        );
    }

    fn is_request(&self) -> bool {
        (self.command_id & 0x80000000) == 0
    }

    fn is_response(&self) -> bool {
        (self.command_id & 0x80000000) != 0
    }

    fn get_response_id(&self) -> u32 {
        if self.is_request() {
            self.command_id | 0x80000000
        } else {
            self.command_id
        }
    }
}

// Extract SMS fields plus UDH indicator
fn extract_sms_data(pdu: &SmppPdu) -> Option<(String, String, u8, Vec<u8>, u8)> {
    let b = &pdu.body;
    // Validación adicional al principio
    if b.len() < 20 {  // Tamaño mínimo razonable para un SubmitSM
        return None;
    }
    
    let mut pos = 0;
    while pos < b.len() && b[pos] != 0 {
        pos += 1;
    }
    pos += 1; // service_type
    pos += 2; // source TON+NPI
    let start_src = pos;
    while pos < b.len() && b[pos] != 0 {
        pos += 1;
    }
    let source = String::from_utf8_lossy(&b[start_src..pos]).to_string();
    pos += 1;
    pos += 2; // dest TON+NPI
    let start_dst = pos;
    while pos < b.len() && b[pos] != 0 {
        pos += 1;
    }
    let destination = String::from_utf8_lossy(&b[start_dst..pos]).to_string();
    pos += 1;
    if pos >= b.len() {
        return None;
    }
    let esm_class = b[pos];
    pos += 1;
    pos += 2; // protocol_id + priority_flag
    while pos < b.len() && b[pos] != 0 {
        pos += 1;
    }
    pos += 1; // schedule_delivery_time
    while pos < b.len() && b[pos] != 0 {
        pos += 1;
    }
    pos += 1; // validity_period
    pos += 2; // registered_delivery + replace_if_present
    if pos >= b.len() {
        return None;
    }
    let data_coding = b[pos];
    pos += 1;
    pos += 1; // sm_default_msg_id
    if pos >= b.len() {
        return None;
    }
    let sm_length = b[pos] as usize;
    pos += 1;
    if pos + sm_length > b.len() {
        return None;
    }
    let message_data = b[pos..pos + sm_length].to_vec();
    Some((source, destination, data_coding, message_data, esm_class))
}

// Extraer las partes del cuerpo SMPP para mensajes concatenados
fn extract_smpp_body_parts(pdu: &SmppPdu) -> Option<(Vec<u8>, Vec<u8>, usize)> {
    let b = &pdu.body;
    
    // Encontrar la posición del sm_length
    let mut pos = 0;
    // service_type
    while pos < b.len() && b[pos] != 0 { pos += 1; }
    pos += 1;                  // null
    pos += 2;                  // TON+NPI
    while pos < b.len() && b[pos] != 0 { pos += 1; }
    pos += 1;                  // null
    pos += 2;                  // TON+NPI
    while pos < b.len() && b[pos] != 0 { pos += 1; }
    pos += 1;                  // null
    pos += 3;                  // esm_class + proto_id + priority
    while pos < b.len() && b[pos] != 0 { pos += 1; }
    pos += 1;                  // sched_deliv_time
    while pos < b.len() && b[pos] != 0 { pos += 1; }
    pos += 1;                  // validity_period
    pos += 2;                  // reg_delivery + replace_if
    pos += 1;                  // data_coding
    pos += 1;                  // sm_default_msg_id
    
    // sm_length_pos es donde está el byte sm_length
    let sm_length_pos = pos;
    
    if sm_length_pos >= b.len() {
        return None;
    }
    
    let sm_length = b[sm_length_pos] as usize;
    let sm_content_pos = sm_length_pos + 1;
    
    if sm_content_pos + sm_length > b.len() {
        return None;
    }
    
    let opt_start = sm_content_pos + sm_length;
    
    // Prefijo: todo antes del contenido del mensaje
    let prefix = b[0..sm_length_pos].to_vec();
    
    // Sufijo: todo después del contenido del mensaje (TLVs opcionales)
    let suffix = if opt_start < b.len() {
        b[opt_start..].to_vec()
    } else {
        Vec::new()
    };
    
    Some((prefix, suffix, sm_length_pos))
}


async fn handle_connection(
    client_stream: TcpStream,
    client_addr:  SocketAddr,
    config:          OperatorConfig,
    sessions:     Arc<Mutex<HashMap<String, SocketAddr>>>,
    buffer:       SharedSmsBuffer,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::ErrorKind;
    use tokio::io::split;
    use tokio::sync::mpsc;
    use tokio::time::sleep;
    use std::time::Duration;
    use std::mem;
    use std::os::unix::io::AsRawFd;

    // 1) Leer BIND desde el cliente
    let mut client = client_stream;

    // Activar TCP keepalive para el cliente usando libc directamente
    unsafe {
        let fd = client.as_raw_fd();
        let val: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &val as *const _ as *const libc::c_void,
            mem::size_of_val(&val) as libc::socklen_t,
        ) != 0 {
            eprintln!("Error setting keepalive for client: {}", std::io::Error::last_os_error());
        }
    }

    let bind_req = SmppPdu::read_from(&mut client).await?;
    bind_req.log();    

    // 2) Conectar al SMSC y reenviar el BIND
    // 2) Conectar al SMSC y reenviar el BIND
    let mut smsc = TcpStream::connect((config.smsc_host.as_str(), config.smsc_port)).await?;
    
    // Activar TCP keepalive para el SMSC
    unsafe {
        let fd = smsc.as_raw_fd();
        let val: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &val as *const _ as *const libc::c_void,
            mem::size_of_val(&val) as libc::socklen_t,
        ) != 0 {
            eprintln!("Error setting keepalive for SMSC: {}", std::io::Error::last_os_error());
        }
    }
    
    println!("[{}] connected to SMSC", config.name);
    bind_req.write_to(&mut smsc).await?;

    // 3) Leer BIND_RESP del SMSC y reenviarlo al cliente
    let bind_resp = SmppPdu::read_from(&mut smsc).await?;
    bind_resp.log();
    bind_resp.write_to(&mut client).await?;
    println!("[{}] bound successfully", config.name);

    // Registrar sesión
    sessions.lock().unwrap().insert(config.system_id.clone(), client_addr);

    // 4) Split de cada stream solo UNA vez
    let (mut cr, mut cw) = split(client);
    let (sr, mut sw) = split(smsc);

    // 5) Canales de forwarding
    let (tx_smsc, mut rx_client) = mpsc::channel::<SmppPdu>(100);
    let (tx_client, mut rx_smsc) = mpsc::channel::<SmppPdu>(100);

    let enquire_interval = Duration::from_secs(45); 

    // 6) Keep-alive: enviar enquire_link cada 30s
    {
        let tx = tx_smsc.clone();
        tokio::spawn(async move {
            loop {
                //sleep(Duration::from_secs(30)).await;
                sleep(enquire_interval).await;
                // Usar new_with_next_seq para obtener un sequence number único
                let pdu = SmppPdu::new_with_next_seq(CMD_ENQUIRE_LINK, ESME_ROK, Vec::new());
                println!("→ Sending ENQUIRE_LINK to SMSC (seq={})", pdu.sequence_number);
                if tx.send(pdu).await.is_err() { break; }
            }
        });
    }

    // 7) Preparamos nombre del operador y clones que necesitamos
    let op        = Arc::new(config.name.clone());
    let tx_client_cr = tx_client.clone();
    //let tx_client_sr = tx_client.clone();
    let op_cr        = op.clone();
    //let op_sr        = op.clone();
    let buf_cr       = buffer.clone();
    let tx_smsc_cr   = tx_smsc.clone();

    // 8) Tarea: Cliente → SMSC
    let client_to_smsc = {
        let mut cr = cr;
        let tx_smsc_cr = tx_smsc.clone();
        let tx_client_cr = tx_client.clone();
        let tx_client_sr = tx_client.clone();
        let buf_cr = buffer.clone();
        let op_cr = op.clone();
        let op_sr = op.clone();

        tokio::spawn(async move {
            loop {
                match SmppPdu::read_from(&mut cr).await {
                    Ok(pdu) => {
                        if pdu.command_id == 0 { break; }
                        pdu.log();
                        println!("→ [{}] Recibido del cliente: cmd=0x{:08X} seq={}", 
                                op_cr, pdu.command_id, pdu.sequence_number);

                        // Manejar diferentes tipos de PDU
                        match pdu.command_id {
                            CMD_UNBIND => {
                                println!("[{}] Received UNBIND from client", op_cr);
                                let resp = SmppPdu::new_response(&pdu, CMD_UNBIND_RESP, ESME_ROK, Vec::new());
                                let _ = tx_client_cr.send(resp).await;
                                break;
                            },
                            CMD_ENQUIRE_LINK => {
                                println!("[{}] Received ENQUIRE_LINK from client", op_cr);
                                let resp = SmppPdu::new_response(&pdu, CMD_ENQUIRE_LINK_RESP, ESME_ROK, Vec::new());
                                let _ = tx_client_cr.send(resp).await;
                                continue;
                            },
                            CMD_SUBMIT_SM => {
                                // Procesar posible mensaje fragmentado
                                if let Some((src, dst, dc, msg_data, esm)) = extract_sms_data(&pdu) {
                                    if esm & 0x40 != 0 && !msg_data.is_empty() {
                                        // Extraer información de UDH del mensaje
                                        if let Some(frag_info) = process_udh(&msg_data, &src, &dst, dc) {
                                            let resp = SmppPdu::new_response(&pdu, CMD_SUBMIT_SM_RESP, ESME_ROK, Vec::new());
                                            // Extraer partes del cuerpo del PDU para reconstrucción posterior
                                            if let Some((prefix, suffix, _)) = extract_smpp_body_parts(&pdu) {

                                                // IMPORTANTE: Enviar respuesta inmediata al cliente para este fragmento
                                                // Dentro del manejo de CMD_SUBMIT_SM (en client_to_smsc task)
                                                let message_id = format!("MSG_ID_{}\0", pdu.sequence_number); // Genera un ID único
                                                let resp_body = message_id.into_bytes(); // Convierte a bytes (incluye el NULL)
                                                let resp = SmppPdu::new_response(&pdu, CMD_SUBMIT_SM_RESP, ESME_ROK, resp_body);
                                                //let resp = SmppPdu::new_response(&pdu, CMD_SUBMIT_SM_RESP, ESME_ROK, Vec::new());
                                                println!("[{}] Sending immediate SUBMIT_SM_RESP to client (seq={})",
                                                    op_cr, resp.sequence_number);
                                                let _ = tx_client_cr.send(resp).await; 

                                                // Añadir al buffer y verificar si se completó
                                                if buf_cr.add_fragment(frag_info.clone(), &prefix, &suffix, pdu.sequence_number) {
                                                    println!("[{}] Message ID {:08X} complete!", op_cr, frag_info.message_id);

                                                    // Recuperar fragmentos ordenados y PDU info original
                                                    if let (Some(ordered_parts), Some((orig_prefix, orig_suffix, orig_seq_num))) =
                                                        (buf_cr.get_fragments_if_complete(frag_info.message_id),
                                                         buf_cr.get_original_pdu_info(frag_info.message_id))
                                                    {
                                                        let total = ordered_parts.len();
                                                        println!("[{}] Sending {} ordered parts to SMSC for message ID {:08X}", 
                                                                op_cr, total, frag_info.message_id);

                                                        // Enviar cada parte como una PDU separada con sequence_number único
                                                        for (i, part) in ordered_parts.into_iter().enumerate() {
                                                            // Generar un nuevo sequence_number único para cada parte
                                                            let seq = SEQUENCE_COUNTER.fetch_add(1, Ordering::SeqCst);
                                                            // Registrar este sequence_number como perteneciente a un fragmento
                                                            register_fragment_sequence(seq);

                                                            // Construir el body para esta parte específica
                                                            let mut part_body = Vec::new();
                                                            part_body.extend_from_slice(&orig_prefix);
                                                            part_body.push(part.content.len() as u8); // sm_length
                                                            part_body.extend_from_slice(&part.content); // short_message (UDH+payload)
                                                            part_body.extend_from_slice(&orig_suffix); // TLVs opcionales

                                                            let part_pdu = SmppPdu::new(
                                                                CMD_SUBMIT_SM,
                                                                ESME_ROK,
                                                                seq, // Usar un sequence number único
                                                                part_body,
                                                            );

                                                            println!("[{}] Sending part {}/{} of message ID {:08X} to SMSC (seq={})",
                                                                   op_cr, part.part_number, total, frag_info.message_id, seq);
                                                            
                                                            if tx_smsc_cr.send(part_pdu).await.is_err() {
                                                                eprintln!("[{}] Failed to send part to SMSC (channel closed)", op_cr);
                                                                // Limpiar el buffer
                                                                buf_cr.remove_message(frag_info.message_id);
                                                                break;
                                                            }
                                                            // Pausa opcional para no saturar el SMSC
                                                            sleep(Duration::from_millis(10)).await;
                                                        }
                                                        // Limpiar el mensaje del buffer después de enviar todas las partes exitosamente
                                                        if buf_cr.remove_message(frag_info.message_id) {
                                                            println!("[{}] Removed message ID {:08X} from buffer after successful sending",
                                                                   op_cr, frag_info.message_id);
                                                        }
                                                    } else {
                                                        // No debería ocurrir, pero por si acaso
                                                        eprintln!("[{}] Message marked complete but couldn't retrieve parts/info", op_cr);
                                                        buf_cr.remove_message(frag_info.message_id);
                                                    }
                                                } else {
                                                    // Fragmento añadido pero mensaje incompleto
                                                    println!("[{}] Fragment added for message ID {:08X}, waiting for more parts", 
                                                            op_cr, frag_info.message_id);
                                                }
                                                // No reenviar el PDU original fragmentado
                                                continue;
                                            }
                                        }
                                    }
                                }
                                // Si no es fragmentado o no se pudo procesar, reenviar normalmente
                                println!("[{}] Forwarding SUBMIT_SM to SMSC", op_cr);
                                let _ = tx_smsc_cr.send(pdu).await;
                            },
                            /*
                            CMD_SUBMIT_SM_RESP => {
                                println!("[{}] Received SUBMIT_SM_RESP from SMSC (seq={})",
                                       op_sr, pdu.sequence_number);
                                
                                // NO reenviar al cliente si es respuesta a un fragmento
                                // Verificar si este sequence_number corresponde a uno de nuestros fragmentos enviados
                                if is_fragment_sequence(pdu.sequence_number) {
                                    println!("[{}] Not forwarding fragment response to client", op_sr);
                                    // No hacer tx_client_sr.send(pdu)
                                } else {
                                    // Solo reenviar si era un mensaje normal (no fragmentado)
                                    println!("[{}] Forwarding regular response to client", op_sr);
                                    let _ = tx_client_sr.send(pdu).await;
                                }
                            },
                            */                      
                            // Otros comandos: simplemente reenviar
                            _ => {
                                println!("[{}] Forwarding PDU type 0x{:08X} to SMSC", op_cr, pdu.command_id);
                                let _ = tx_smsc_cr.send(pdu).await;
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                        println!("[{}] client disconnected", op_cr);
                        break;
                    }
                    Err(e) => {
                        eprintln!("[{}] client read error: {}", op_cr, e);
                        break;
                    }
                }
            }
        })
    };


    // 9) Tarea: SMSC → Cliente
    let smsc_to_client = {
        // Clonamos solo lo que necesitamos para esta tarea
        let mut sr = sr;
        let tx_client_sr = tx_client.clone();
        let tx_smsc_clone = tx_smsc.clone();
        let op_sr = op.clone();
    
        tokio::spawn(async move {
            loop {
                match SmppPdu::read_from(&mut sr).await {
                    Ok(pdu) => {
                        if pdu.command_id == 0 {
                            // socket cerrado del otro extremo
                            break;
                        }                        
                        pdu.log();
                        println!(
                            "→ [{}] Recibido del SMSC: cmd=0x{:08X} seq={}",
                            op_sr, pdu.command_id, pdu.sequence_number
                        );
    
                        match pdu.command_id {
                            CMD_DELIVER_SM => {
                                println!("[{}] Received DELIVER_SM from SMSC", op_sr);
                                // Forward al cliente
                                let _ = tx_client_sr.send(pdu.clone()).await;
                                // Responder al SMSC
                                let resp = SmppPdu::new_response(
                                    &pdu,
                                    CMD_DELIVER_SM_RESP,
                                    ESME_ROK,
                                    Vec::new(),
                                );
                                println!(
                                    "[{}] Sending DELIVER_SM_RESP to SMSC (seq={})",
                                    op_sr, resp.sequence_number
                                );
                                let _ = tx_smsc_clone.send(resp).await;
                            }
                            CMD_ENQUIRE_LINK => {
                                println!("[{}] Received ENQUIRE_LINK from SMSC", op_sr);
                                // Responder al SMSC
                                let resp = SmppPdu::new_response(
                                    &pdu,
                                    CMD_ENQUIRE_LINK_RESP,
                                    ESME_ROK,
                                    Vec::new(),
                                );
                                println!(
                                    "[{}] Sending ENQUIRE_LINK_RESP to SMSC (seq={})",
                                    op_sr, resp.sequence_number
                                );
                                let _ = tx_smsc_clone.send(resp).await;
                            }
                            CMD_ENQUIRE_LINK_RESP => {
                                println!(
                                    "[{}] Received ENQUIRE_LINK_RESP from SMSC (seq={})",
                                    op_sr, pdu.sequence_number
                                );
                                // No further action
                            }
                            CMD_DATA_SM => {
                                println!("[{}] Received DATA_SM from SMSC", op_sr);
                                // Forward al cliente
                                let _ = tx_client_sr.send(pdu.clone()).await;
                                // Responder al SMSC
                                let resp = SmppPdu::new_response(
                                    &pdu,
                                    CMD_DATA_SM_RESP,
                                    ESME_ROK,
                                    Vec::new(),
                                );
                                println!(
                                    "[{}] Sending DATA_SM_RESP to SMSC (seq={})",
                                    op_sr, resp.sequence_number
                                );
                                let _ = tx_smsc_clone.send(resp).await;
                            }
                            // Respuestas a nuestros SubmitSM (fragmentos o normales)
                            /*
                            _ if pdu.is_response() => {
                                println!(
                                    "[{}] Forwarding response PDU to client: cmd=0x{:08X} seq={}",
                                    op_sr, pdu.command_id, pdu.sequence_number
                                );
                                let _ = tx_client_sr.send(pdu).await;
                            }
                            */
                            _ if pdu.is_response() => {
                                // Verificar si es una respuesta a un fragmento
                                if is_fragment_sequence(pdu.sequence_number) {
                                    println!(
                                        "[{}] Not forwarding fragment response to client (seq={})",
                                        op_sr, pdu.sequence_number
                                    );
                                    // Eliminar el sequence_number del registro
                                    FRAGMENT_SEQUENCES.write().unwrap().remove(&pdu.sequence_number);
                                } else {
                                    println!(
                                        "[{}] Forwarding response PDU to client: cmd=0x{:08X} seq={}",
                                        op_sr, pdu.command_id, pdu.sequence_number
                                    );
                                    let _ = tx_client_sr.send(pdu).await;
                                }
                            }                            
                            // Cualquier otra solicitud
                            _ => {
                                println!(
                                    "[{}] Forwarding request PDU to client: cmd=0x{:08X} seq={}",
                                    op_sr, pdu.command_id, pdu.sequence_number
                                );
                                let _ = tx_client_sr.send(pdu).await;
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                        println!("[{}] SMSC disconnected", op_sr);
                        break;
                    }
                    Err(e) => {
                        eprintln!("[{}] SMSC read error: {}", op_sr, e);
                        break;
                    }
                }
            }
        })
    };
    
    // 10) Writers: enviar desde canales a sockets
    let client_writer = tokio::spawn(async move {
        while let Some(pdu) = rx_smsc.recv().await {
            if pdu.write_to(&mut cw).await.is_err() {
                break;
            }
        }
    });
    let smsc_writer = tokio::spawn(async move {
        while let Some(pdu) = rx_client.recv().await {
            if pdu.write_to(&mut sw).await.is_err() {
                break;
            }
        }
    });

    // 11) Esperar a que termine alguna tarea
    let (_r1, _r2, _r3, _r4) = tokio::join!(
        client_to_smsc,
        smsc_to_client,
        client_writer,
        smsc_writer,
    );
    
    // 12) Cerrar sesión
    sessions.lock().unwrap().remove(&config.system_id);
    println!("[{}] session closed", config.name);
    Ok(())}



    fn load_config(path: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
        let yaml_content = fs::read_to_string(path)?;
        let config: AppConfig = serde_yaml::from_str(&yaml_content)?;
        Ok(config)
    }
    
    #[tokio::main]
    async fn main() -> Result<(), Box<dyn std::error::Error>> {
        let config = load_config("config.yaml")?;
    
        for operator in &config.operators {
            let cfg = operator.clone();
            
            tokio::spawn(async move {
                let interceptor = SmppInterceptor::new(cfg.clone());
                interceptor.run().await.unwrap_or_else(|e| {
                    eprintln!("[{}] Error: {}", cfg.name, e);
                });
            });
        }
    
        // Mantener el programa activo
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }