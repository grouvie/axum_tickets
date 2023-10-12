#[derive(Clone, Debug)]
pub struct Ctx {
    user_id: usize,
}

// Constructor.
impl Ctx {
    pub fn new(user_id: usize) -> Self {
        Self { user_id }
    }
}

// Property Accessors.
impl Ctx {
    pub fn user_id(&self) -> usize {
        self.user_id
    }
}
