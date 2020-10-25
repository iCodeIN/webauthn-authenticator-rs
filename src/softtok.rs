
use crate::U2FToken;
use crate::error::WebauthnCError;
use crate::{U2FSignData, U2FRegistrationData};
use webauthn_rs::proto::AllowCredentials;

pub struct U2FSoft {
}

impl U2FSoft {
    pub fn new() -> Self {
        U2FSoft { }
    }
}

impl U2FToken for U2FSoft {
    fn perform_u2f_register(
        &self,
        // This is rp.id_hash
        app_bytes: Vec<u8>,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        timeout_ms: u64,
        //
        platform_attached: bool,
        resident_key: bool,
        user_verification: bool,
    ) -> Result<U2FRegistrationData, WebauthnCError> {
        unimplemented!();
    }

    fn perform_u2f_sign(
        &self,
        // This is rp.id_hash
        app_bytes: Vec<u8>,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        timeout_ms: u64,
        // list of creds
        allowed_credentials: &[AllowCredentials],
        user_verification: bool,
    ) -> Result<U2FSignData, WebauthnCError> {
        unimplemented!();
    }
}
