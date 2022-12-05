pub const MEASUREMENT_CACHE_FLUSH: i64 = 60; // every min
pub const TCP_CONNECTION_TIMEOUT: i64 = 60;
pub const UDP_CONNECTION_TIMEOUT: i64 = 60;

use std::{collections::{HashMap, HashSet}, mem};

use crate::{ocsp_struct::OCSP_MEASURE, common::Flow};


pub struct MeasurementCache {
    pub last_flush: time::Tm,
    pub ocsp_measurements_new: HashMap<Flow, OCSP_MEASURE>,
    ocsp_measurements_flushed: HashSet<Flow>,
}

impl MeasurementCache {
    pub fn new() -> MeasurementCache {
        MeasurementCache {
            last_flush: time::now(),
            ocsp_measurements_new: HashMap::new(),
            ocsp_measurements_flushed: HashSet::new(),
        }
    }

    pub fn add_ocsp_measurement(&mut self, flow: &Flow, ocsp: OCSP_MEASURE) {
        if !self.ocsp_measurements_flushed.contains(&flow) {
            self.ocsp_measurements_new.insert(*flow, ocsp);
        }
    }

    pub fn flush_ocsp_measurements(&mut self) -> HashMap<Flow, OCSP_MEASURE> {
        self.last_flush = time::now();
        for (flow, _ocsp) in self.ocsp_measurements_new.iter_mut() {
            self.ocsp_measurements_flushed.insert(*flow);
        }
        mem::replace(&mut self.ocsp_measurements_new, HashMap::new())
    }
}