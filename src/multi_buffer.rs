use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::sleep;

use crate::sms_fragment::{SharedSmsBuffer, ReconstructedMessage, start_cleanup_thread};

/// Estadísticas globales
#[derive(Debug, Default, Clone)]
pub struct GlobalStats {
    pub total_messages_received: u64,
    pub messages_by_operator: HashMap<String, u64>,
    pub current_buffer_sizes: HashMap<String, usize>,
    pub tps_by_operator: HashMap<String, f64>,
}

/// Configuración por operador
#[derive(Clone)]
pub struct OperatorConfig {
    pub max_tps: u32,
    pub expiry_time_secs: u64,
    pub name: String,
    pub semaphore: Arc<Semaphore>,
}

/// Gestor de buffers múltiples
pub struct MultiBufferManager {
    buffers: HashMap<String, SharedSmsBuffer>,
    configs: HashMap<String, OperatorConfig>,
    stats: Arc<Mutex<GlobalStats>>,
}

impl MultiBufferManager {
    pub fn new(operator_configs: Vec<(String, u32, u64)>) -> Self {
        let mut buffers = HashMap::new();
        let mut configs = HashMap::new();
        let mut stats = GlobalStats::default();

        for (name, _, _) in &operator_configs {
            stats.messages_by_operator.insert(name.clone(), 0);
            stats.current_buffer_sizes.insert(name.clone(), 0);
            stats.tps_by_operator.insert(name.clone(), 0.0);
        }

        for (name, max_tps, expiry) in operator_configs {
            let buffer = SharedSmsBuffer::new(expiry);
            start_cleanup_thread(buffer.clone(), 60);

            let config = OperatorConfig {
                max_tps,
                expiry_time_secs: expiry,
                name: name.clone(),
                semaphore: Arc::new(Semaphore::new(max_tps as usize)),
            };

            buffers.insert(name.clone(), buffer);
            configs.insert(name, config);
        }

        let manager = MultiBufferManager {
            buffers,
            configs,
            stats: Arc::new(Mutex::new(stats)),
        };

        manager.start_rate_limiters();
        manager
    }

    pub fn get_buffer(&self, operator: &str) -> Option<SharedSmsBuffer> {
        self.buffers.get(operator).cloned()
    }

    pub fn setup_callbacks(&self) {
        for (op_name, buffer) in &self.buffers {
            let stats = Arc::clone(&self.stats);
            let op = op_name.clone();
            buffer.set_message_callback(move |msg: ReconstructedMessage| {
                let mut st = stats.lock().unwrap();
                st.total_messages_received += 1;
                *st.messages_by_operator.entry(op.clone()).or_insert(0) += 1;
                println!(
                    "[{}] Reconstructed ID {:08X} → {} parts",
                    op, msg.message_id, msg.total_parts
                );
            });
        }
    }

    fn start_rate_limiters(&self) {
        for (op_name, cfg) in &self.configs {
            let sem = Arc::clone(&cfg.semaphore);
            let max_tps = cfg.max_tps;
            let stats = Arc::clone(&self.stats);
            let op = op_name.clone();

            tokio::spawn(async move {
                let mut used = 0;
                let mut last = Instant::now();
                loop {
                    sleep(Duration::from_millis(100)).await;
                    if last.elapsed() >= Duration::from_secs(1) {
                        let mut st = stats.lock().unwrap();
                        st.tps_by_operator.insert(op.clone(), used as f64);
                        let avail = sem.available_permits();
                        if avail < max_tps as usize {
                            sem.add_permits(max_tps as usize - avail);
                        }
                        used = 0;
                        last = Instant::now();
                    }
                    used = max_tps as usize - sem.available_permits();
                }
            });
        }
    }

    pub fn get_stats(&self) -> GlobalStats {
        let mut st = self.stats.lock().unwrap().clone();
        // actualizamos tamaños de buffer
        for (name, buf) in &self.buffers {
            st.current_buffer_sizes.insert(name.clone(), buf.message_count());
        }
        st
    }

    pub fn adjust_operator_tps(&self, operator: &str, new_tps: u32) -> bool {
        if let Some(cfg) = self.configs.get(operator) {
            let avail = cfg.semaphore.available_permits();
            if new_tps as usize > avail {
                cfg.semaphore.add_permits(new_tps as usize - avail);
            }
            println!("Adjusted {} TPS → {} for {}", avail, new_tps, operator);
            true
        } else {
            false
        }
    }
}

/// Inicializa el sistema completo
pub fn setup_multi_buffer_system() -> MultiBufferManager {
    let ops = vec![
        ("ENTEL".to_string(), 20, 300),
        ("MOVISTAR".to_string(), 20, 300),
        ("CLARO".to_string(), 20, 300),
        ("BITEL".to_string(), 20, 300),
    ];
    let mgr = MultiBufferManager::new(ops);
    mgr.setup_callbacks();
    mgr
}