use justrdp_derive::Encode;

#[derive(Encode)]
pub struct Bad {
    pub field: u8,
}

fn main() {}
