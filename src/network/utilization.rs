use crate::network::{Connection, Direction, Segment};

use hdrhistogram::{Histogram};
use ::std::collections::HashMap;

#[derive(Clone)]
pub struct ConnectionInfo {
    pub interface_name: String,
    pub total_bytes_downloaded: u128,
    pub total_bytes_uploaded: u128,
    pub total_bytes_downloaded_hist: Histogram<u64>,
    pub total_bytes_uploaded_hist: Histogram<u64>,
}

#[derive(Clone)]
pub struct Utilization {
    pub connections: HashMap<Connection, ConnectionInfo>,
}

impl Utilization {
    pub fn new() -> Self {
        let connections = HashMap::new();
        Utilization { connections }
    }
    pub fn clone_and_reset(&mut self) -> Self {
        let clone = self.clone();
        self.connections.clear();
        clone
    }
    pub fn update(&mut self, seg: Segment) {
        let total_bandwidth = self
            .connections
            .entry(seg.connection)
            .or_insert(ConnectionInfo {
                interface_name: seg.interface_name,
                total_bytes_downloaded: 0,
                total_bytes_uploaded: 0,
                total_bytes_downloaded_hist: Histogram::new(2).unwrap(),
                total_bytes_uploaded_hist: Histogram::new(2).unwrap(),
            });
        match seg.direction {
            Direction::Download => {
                total_bandwidth.total_bytes_downloaded += seg.data_length;
                total_bandwidth.total_bytes_downloaded_hist += seg.data_length as u64;
            }
            Direction::Upload => {
                total_bandwidth.total_bytes_uploaded += seg.data_length;
                total_bandwidth.total_bytes_uploaded_hist += seg.data_length as u64;
            }
        }
    }
}
