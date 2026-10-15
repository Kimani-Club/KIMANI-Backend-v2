use serde::Deserialize;

use super::client::Ping;

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ClientMessage {
    Authenticate { token: String, #[serde(default)] auth0_token: Option<String> },
    BeginTyping { channel: String },
    EndTyping { channel: String },
    Ping { data: Ping, responded: Option<()> },
}
