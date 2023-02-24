pub trait Screen {
    fn activate(&mut self) {}
    fn deactivate(&mut self) {}
    fn focus(&mut self) {}
    fn unfocus(&mut self) {}
}
