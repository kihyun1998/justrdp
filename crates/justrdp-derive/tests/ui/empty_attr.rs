use justrdp_derive::Encode;

#[derive(Encode)]
pub struct Bad {
    #[pdu()]
    pub field: u8,
}

fn main() {}
