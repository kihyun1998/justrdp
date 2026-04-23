#![forbid(unsafe_code)]

//! RDPSND PDU types -- MS-RDPEA 2.2

mod header;
mod audio_format;
mod formats;
mod quality;
mod training;
mod wave;
mod wave_confirm;
mod volume;

pub use header::{SndHeader, SndMsgType, SND_HEADER_SIZE};
pub use audio_format::{AudioFormat, WaveFormatTag};
pub use formats::{ServerAudioFormatsPdu, ClientAudioFormatsPdu, ClientSndFlags, ServerSndCapsFlags};
pub use quality::{QualityModePdu, QualityMode};
pub use training::{TrainingPdu, TrainingConfirmPdu};
pub use wave::{WaveInfoPdu, Wave2Pdu, decode_wave_data, encode_wave_pdu_body};
pub use wave_confirm::WaveConfirmPdu;
pub use volume::VolumePdu;
