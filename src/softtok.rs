
use crate::U2FToken;
use crate::error::WebauthnCError;
use crate::{U2FSignData, U2FRegistrationData};
use webauthn_rs::proto::AllowCredentials;

use openssl::{sign, hash, ec, nid, pkey, bn};

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
        if user_verification {
            log::error!("User Verification not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        if platform_attached {
            log::error!("Platform Attachement not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        if resident_key {
            log::error!("Resident Keys not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }

        // Create a new key.
        let ecgroup = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        let eckey = ec::EcKey::generate(&ecgroup)
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        // Extract the public x and y coords.
        let ecpub_points = eckey.public_key();

        let mut bnctx = bn::BigNumContext::new()
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        let mut xbn = bn::BigNum::new()
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        let mut ybn = bn::BigNum::new()
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        ecpub_points.affine_coordinates_gfp(&ecgroup
            &mut xbn,
            &mut ybn,
            &mut bnctx,
        )
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        let public_key_x = xbn.to_vec();
        let public_key_y = ybn.to_vec();

        // Extract the DER cert for later
        let ecpriv_der = eckey.private_key_to_der()
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        // Now setup to sign.
        let pkey = pkey::PKey::from_ec_key(eckey)
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        let signer = sign::Signer::new(hash::MessageDigest::sha256(), &pkey)
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        // Do the signature
        let signature = signer.update(verification_data)
            .and_then(|_| {
                signer.sign_to_vec()
            })
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        // WARNING: This is lollll
        let att_cert: Vec::new();

        let u2rd = U2FRegistrationData {
            public_key_x,
            public_key_y,
            key_handle,
            att_cert,
            signature,
        };

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
        if user_verification {
            log::error!("User Verification not supported by softtoken");
            return Err(WebauthnCError::NotSupported);
        }
    }
}
