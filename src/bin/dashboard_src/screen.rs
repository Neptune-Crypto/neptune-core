use std::sync::Arc;

use super::dashboard_app::DashboardEvent;

pub trait Screen {
    fn activate(&mut self) {}
    fn deactivate(&mut self) {}
    fn focus(&mut self) {}
    fn unfocus(&mut self) {}
    fn escalatable_event(&self) -> Arc<std::sync::Mutex<Option<DashboardEvent>>>;
}
