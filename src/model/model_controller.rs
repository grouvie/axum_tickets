use crate::Result;
use std::sync::{ Arc, Mutex };

use crate::model::tickets::Ticket;

#[derive(Clone)]
pub(crate) struct ModelController {
    pub(crate) tickets_store: Arc<Mutex<Vec<Option<Ticket>>>>,
}

impl ModelController {
    pub(crate) async fn new() -> Result<Self> {
        Ok(Self {
            tickets_store: Arc::default(),
        })
    }
}
