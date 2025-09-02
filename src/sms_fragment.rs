use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

/// Estadísticas del buffer de fragmentos
#[derive(Debug, Default, Clone)]
pub struct BufferStats {
    pub fragments_received: usize,
    pub messages_completed: usize,
    pub messages_expired: usize,
    pub fragments_duplicated: usize,
}

/// Información de un fragmento de mensaje (UDH + payload)
#[derive(Debug, Clone)]
pub struct FragmentInfo {
    pub message_id: u32,
    pub part_number: u8,
    pub total_parts: Option<u8>,
    pub content: Vec<u8>,    // **raw** UDH + texto
    pub source: String,
    pub destination: String,
    pub data_coding: u8,
}

/// Resultado de reconstrucción (solo para callback/log)
#[derive(Debug, Clone)]
pub struct ReconstructedMessage {
    pub message_id: u32,
    pub source: String,
    pub destination: String,
    pub content: Vec<u8>,
    pub total_parts: u8,
    pub data_coding: u8,
    pub timestamp: Instant,
}

struct SmsMessage {
    source: String,
    destination: String,
    total_parts: Option<u8>,
    parts: HashMap<u8, FragmentInfo>,
    timestamp: Instant,
    completed: bool,
    data_coding: u8,
    // Nueva información para almacenar partes del PDU original
    original_prefix: Vec<u8>,
    original_suffix: Vec<u8>,
    original_seq_num: u32,
}

/// Buffer principal
pub struct SmsFragmentBuffer {
    buffer: HashMap<u32, SmsMessage>,
    expiry_time: Duration,
    stats: BufferStats,
    message_callback: Option<Box<dyn Fn(ReconstructedMessage) + Send + Sync>>,
}

impl SmsFragmentBuffer {
    pub fn new(expiry_time_secs: u64) -> Self {
        Self {
            buffer: HashMap::new(),
            expiry_time: Duration::from_secs(expiry_time_secs),
            stats: BufferStats::default(),
            message_callback: None,
        }
    }

    pub fn set_message_callback<F>(&mut self, cb: F)
    where F: Fn(ReconstructedMessage) + Send + Sync + 'static {
        self.message_callback = Some(Box::new(cb));
    }

    /// Agrega un fragmento; si completa, devuelve true
    pub fn add_fragment(&mut self, frag: FragmentInfo, prefix: &[u8], suffix: &[u8], seq_num: u32) -> bool {
        self.stats.fragments_received += 1;
        let entry = self.buffer.entry(frag.message_id).or_insert_with(|| SmsMessage {
            source: frag.source.clone(),
            destination: frag.destination.clone(),
            total_parts: frag.total_parts,
            parts: HashMap::new(),
            timestamp: Instant::now(),
            completed: false,
            data_coding: frag.data_coding,
            original_prefix: prefix.to_vec(),
            original_suffix: suffix.to_vec(),
            original_seq_num: seq_num,
        });

        // Actualizar timestamp
        entry.timestamp = Instant::now();
        
        // Detectar fragmentos duplicados
        if entry.parts.contains_key(&frag.part_number) {
            self.stats.fragments_duplicated += 1;
        }
        
        // Guardar fragmento
        entry.parts.insert(frag.part_number, frag.clone());
        
        // Actualizar total_parts si es necesario
        if entry.total_parts.is_none() {
            entry.total_parts = frag.total_parts;
        }

        // Si ya está marcado como completo, no hacer nada más
        if entry.completed {
            return true;
        }

        // Verificar si el mensaje está completo
        if let Some(total) = entry.total_parts {
            let complete = (1..=total).all(|i| entry.parts.contains_key(&i));
            if complete {
                entry.completed = true;
                self.stats.messages_completed += 1;

                // Crear mensaje reconstruido para el callback
                let mut full_content = Vec::new();
                for i in 1..=total {
                    full_content.extend_from_slice(&entry.parts[&i].content);
                }
                
                let msg = ReconstructedMessage {
                    message_id: frag.message_id,
                    source: entry.source.clone(),
                    destination: entry.destination.clone(),
                    content: full_content,
                    total_parts: total,
                    data_coding: entry.data_coding,
                    timestamp: Instant::now(),
                };
                
                // Llamar al callback si existe
                if let Some(cb) = &self.message_callback {
                    cb(msg);
                }
                
                return true;
            }
        }
        
        false
    }

    /// Obtener fragmentos si el mensaje está completo
    pub fn get_fragments_if_complete(&self, message_id: u32) -> Option<Vec<FragmentInfo>> {
        if let Some(msg) = self.buffer.get(&message_id) {
            if msg.completed {
                let mut v: Vec<_> = msg.parts.values().cloned().collect();
                v.sort_by_key(|f| f.part_number);
                return Some(v);
            }
        }
        None
    }

    /// Obtener información del PDU original
    pub fn get_original_pdu_info(&self, message_id: u32) -> Option<(Vec<u8>, Vec<u8>, u32)> {
        if let Some(msg) = self.buffer.get(&message_id) {
            if msg.completed {
                return Some((
                    msg.original_prefix.clone(),
                    msg.original_suffix.clone(),
                    msg.original_seq_num
                ));
            }
        }
        None
    }

    /// Eliminar explícitamente un mensaje del buffer
    pub fn remove_message(&mut self, message_id: u32) -> bool {
        self.buffer.remove(&message_id).is_some()
    }

    /// Limpia expirados
    pub fn clean_expired_messages(&mut self) -> usize {
        let now = Instant::now();
        let mut removed = 0;
        let ids: Vec<u32> = self.buffer.iter()
            .filter(|(_, m)| !m.completed && now.duration_since(m.timestamp) > self.expiry_time)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.buffer.remove(&id);
            self.stats.messages_expired += 1;
            removed += 1;
        }
        removed
    }

    /// Obtiene todas las partes ordenadas de un mensaje
    pub fn get_fragments(&self, message_id: u32) -> Vec<FragmentInfo> {
        if let Some(msg) = self.buffer.get(&message_id) {
            let mut v: Vec<_> = msg.parts.values().cloned().collect();
            v.sort_by_key(|f| f.part_number);
            v
        } else {
            Vec::new()
        }
    }

    /// Estadísticas internas
    pub fn get_stats(&self) -> BufferStats {
        self.stats.clone()
    }
}

/// Wrapper thread‐safe
#[derive(Clone)]
pub struct SharedSmsBuffer {
    inner: Arc<Mutex<SmsFragmentBuffer>>,
}

impl SharedSmsBuffer {
    pub fn new(expiry: u64) -> Self {
        SharedSmsBuffer {
            inner: Arc::new(Mutex::new(SmsFragmentBuffer::new(expiry))),
        }
    }

    pub fn add_fragment(&self, f: FragmentInfo, prefix: &[u8], suffix: &[u8], seq_num: u32) -> bool {
        let mut b = self.inner.lock().unwrap();
        b.add_fragment(f, prefix, suffix, seq_num)
    }

    pub fn get_fragments_if_complete(&self, msg_id: u32) -> Option<Vec<FragmentInfo>> {
        let b = self.inner.lock().unwrap();
        b.get_fragments_if_complete(msg_id)
    }

    pub fn get_original_pdu_info(&self, msg_id: u32) -> Option<(Vec<u8>, Vec<u8>, u32)> {
        let b = self.inner.lock().unwrap();
        b.get_original_pdu_info(msg_id)
    }

    pub fn remove_message(&self, msg_id: u32) -> bool {
        let mut b = self.inner.lock().unwrap();
        b.remove_message(msg_id)
    }

    pub fn clean_expired_messages(&self) -> usize {
        let mut b = self.inner.lock().unwrap();
        b.clean_expired_messages()
    }

    pub fn get_fragments(&self, msg_id: u32) -> Vec<FragmentInfo> {
        let b = self.inner.lock().unwrap();
        b.get_fragments(msg_id)
    }

    pub fn set_message_callback<F>(&self, cb: F)
    where F: Fn(ReconstructedMessage) + Send + Sync + 'static {
        let mut b = self.inner.lock().unwrap();
        b.set_message_callback(cb);
    }

    /// **NUEVO**: exponer get_stats()
    pub fn get_stats(&self) -> BufferStats {
        let b = self.inner.lock().unwrap();
        b.get_stats()
    }

    /// Para reportes: cuántos mensajes en curso
    pub fn message_count(&self) -> usize {
        let b = self.inner.lock().unwrap();
        b.buffer.len()
    }
}

/// Procesa UDH y devuelve FragmentInfo con raw = UDH+texto
pub fn process_udh(
    short_message: &[u8],
    source: &str,
    destination: &str,
    data_coding: u8
) -> Option<FragmentInfo> {
    if short_message.len() < 6 { return None; }
    let udh_len = short_message[0] as usize;
    if udh_len + 1 > short_message.len() { return None; }

    let mut pos = 1;
    while pos + 2 <= udh_len + 1 && pos + 2 <= short_message.len() {
        let ie_id = short_message[pos];
        let ie_len = short_message[pos + 1] as usize;
        if pos + 2 + ie_len > short_message.len() || pos + 2 + ie_len > udh_len + 1 {
            break;
        }
        match ie_id {
            0x00 if ie_len == 3 => {
                let message_id = short_message[pos+2] as u32;
                let total = short_message[pos+3];
                let part  = short_message[pos+4];
                let raw   = short_message.to_vec();
                return Some(FragmentInfo {
                    message_id,
                    part_number: part,
                    total_parts: Some(total),
                    content: raw,
                    source: source.to_string(),
                    destination: destination.to_string(),
                    data_coding,
                });
            }
            0x08 if ie_len == 4 => {
                let message_id = ((short_message[pos+2] as u32)<<8)
                               |  short_message[pos+3] as u32;
                let total = short_message[pos+4];
                let part  = short_message[pos+5];
                let raw   = short_message.to_vec();
                return Some(FragmentInfo {
                    message_id,
                    part_number: part,
                    total_parts: Some(total),
                    content: raw,
                    source: source.to_string(),
                    destination: destination.to_string(),
                    data_coding,
                });
            }
            0x04 if ie_len >= 3 => {
                let message_id = short_message[pos+2] as u32;
                let part  = short_message[pos+4];
                let raw   = short_message.to_vec();
                return Some(FragmentInfo {
                    message_id,
                    part_number: part,
                    total_parts: None,
                    content: raw,
                    source: source.to_string(),
                    destination: destination.to_string(),
                    data_coding,
                });
            }
            _ => {}
        }
        pos += 2 + ie_len;
    }
    None
}

/// Hilo de limpieza automática
pub fn start_cleanup_thread(buffer: SharedSmsBuffer, interval_secs: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(interval_secs));
        let removed = buffer.clean_expired_messages();
        if removed > 0 {
            println!("Cleanup: {} expired messages", removed);
        }
    });
}

/// Hilo de reporte periódico
pub fn start_report_thread(buffer: SharedSmsBuffer, interval_secs: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(interval_secs));
        let stats = buffer.get_stats();
        println!(
            "Fragments received: {}, completed: {}, expired: {}, duplicates: {}",
            stats.fragments_received,
            stats.messages_completed,
            stats.messages_expired,
            stats.fragments_duplicated,
        );
    });
}