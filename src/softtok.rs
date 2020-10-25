use crate::error::WebauthnCError;
use crate::U2FToken;
use crate::{U2FRegistrationData, U2FSignData};
use openssl::{bn, ec, hash, nid, pkey, rand, sign};
use std::collections::HashMap;
use std::iter;
use webauthn_rs::proto::AllowCredentials;

pub struct U2FSoft {
    tokens: HashMap<Vec<u8>, Vec<u8>>,
    counter: u32,
}

impl U2FSoft {
    pub fn new() -> Self {
        U2FSoft {
            tokens: HashMap::new(),
            counter: 0,
        }
    }
}

impl U2FToken for U2FSoft {
    fn perform_u2f_register(
        &mut self,
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

        // Generate a random credential id
        let mut key_handle: Vec<u8> = Vec::with_capacity(32);
        key_handle.resize_with(32, Default::default);
        rand::rand_bytes(key_handle.as_mut_slice()).map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Create a new key.
        let ecgroup = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let eckey = ec::EcKey::generate(&ecgroup).map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Extract the public x and y coords.
        let ecpub_points = eckey.public_key();

        let mut bnctx = bn::BigNumContext::new().map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let mut xbn = bn::BigNum::new().map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let mut ybn = bn::BigNum::new().map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        ecpub_points
            .affine_coordinates_gfp(&ecgroup, &mut xbn, &mut ybn, &mut bnctx)
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        let public_key_x = xbn.to_vec();
        let public_key_y = ybn.to_vec();

        if public_key_x.len() != 32 || public_key_y.len() != 32 {
            log::error!("OpenSSL BN generated invalid arrays");
            return Err(WebauthnCError::OpenSSL);
        }

        // Extract the DER cert for later
        let ecpriv_der = eckey.private_key_to_der().map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Now setup to sign.
        let pkey = pkey::PKey::from_ec_key(eckey).map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &pkey).map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats])
        let r: [u8; 1] = [0x00];
        let s: [u8; 1] = [0x04];
        let verification_data: Vec<u8> = (&r)
            .iter()
            .chain(app_bytes.iter())
            .chain(chal_bytes.iter())
            .chain(key_handle.iter())
            // This is the public key
            .chain(s.iter())
            .chain(public_key_x.iter())
            .chain(public_key_y.iter())
            .map(|b| *b)
            .collect();

        // Do the signature
        let signature = signer
            .update(verification_data.as_slice())
            .and_then(|_| signer.sign_to_vec())
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        // WARNING: This is lollll
        let att_cert = Vec::new();

        // Okay, now persist the token. We can't fail from here.
        self.tokens.insert(key_handle.clone(), ecpriv_der);

        Ok(U2FRegistrationData {
            public_key_x,
            public_key_y,
            key_handle,
            att_cert,
            signature,
        })
    }

    fn perform_u2f_sign(
        &mut self,
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

        let cred = allowed_credentials
            .iter()
            .filter_map(|ac| {
                self.tokens
                    .get(&ac.id.0)
                    .map(|v| (ac.id.0.clone(), v.clone()))
            })
            .take(1)
            .next();

        let (key_handle, pkder) = if let Some((key_handle, pkder)) = cred {
            (key_handle, pkder)
        } else {
            log::error!("Credential ID not found");
            return Err(WebauthnCError::Internal);
        };

        log::debug!("Using -> {:?}", key_handle);

        let eckey = ec::EcKey::private_key_from_der(pkder.as_slice()).map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let pkey = pkey::PKey::from_ec_key(eckey).map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &pkey).map_err(|e| {
            log::error!("OpenSSL Error -> {:?}", e);
            WebauthnCError::OpenSSL
        })?;

        // Increment the counter.
        self.counter += 1;
        let counter = self.counter;
        let user_present = 1;

        let verification_data: Vec<u8> = app_bytes
            .iter()
            .chain(iter::once(&user_present))
            .chain(counter.to_be_bytes().iter())
            .chain(chal_bytes.iter())
            .map(|b| *b)
            .collect();

        let signature = signer
            .update(verification_data.as_slice())
            .and_then(|_| signer.sign_to_vec())
            .map_err(|e| {
                log::error!("OpenSSL Error -> {:?}", e);
                WebauthnCError::OpenSSL
            })?;

        let appid = Vec::new();

        Ok(U2FSignData {
            appid,
            key_handle,
            counter,
            signature,
            user_present,
        })
    }
}
