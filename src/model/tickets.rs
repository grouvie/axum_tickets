use crate::{ Error, Result, ctx::Ctx };
use serde::{ Deserialize, Serialize };

use crate::model::model_controller::ModelController;

impl ModelController {
    pub async fn create_ticket(&self, ctx: Ctx, ticket_fc: TicketForCreate) -> Result<Ticket> {
        let mut store = self.tickets_store.lock().unwrap();

        let id = store.len();
        let ticket = Ticket {
            id,
            cid: ctx.user_id(),
            title: ticket_fc.title,
        };
        store.push(Some(ticket.clone()));

        Ok(ticket)
    }

    pub async fn list_tickets(&self, _ctx: Ctx) -> Result<Vec<Ticket>> {
        let store = self.tickets_store.lock().unwrap();

        let tickets = store
            .iter()
            .filter_map(|t| t.clone())
            .collect();

        Ok(tickets)
    }

    pub async fn delete_ticket(&self, _ctx: Ctx, id: u64) -> Result<Ticket> {
        let mut store = self.tickets_store.lock().unwrap();

        let ticket = store.get_mut(id as usize).and_then(|t| t.take());

        ticket.ok_or(Error::TicketDeleteFailIdNotFound { id })
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Ticket {
    pub(crate) id: usize,
    pub(crate) cid: usize,
    pub(crate) title: String,
}

#[derive(Deserialize)]
pub(crate) struct TicketForCreate {
    pub(crate) title: String,
}
