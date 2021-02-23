use crate::error::WebauthnCError;
use crate::U2FToken;
use crate::{U2FRegistrationData, U2FSignData};
use webauthn_rs::proto::AllowCredentials;

use std::convert::TryFrom;

use authenticator::{
    authenticatorservice::AuthenticatorService, statecallback::StateCallback,
    AuthenticatorTransports, KeyHandle, RegisterFlags, SignFlags, StatusUpdate,
};
use std::sync::mpsc::channel;
use std::thread;

pub struct U2FHid {}

// The format of the return registration data is as follows:
//
// Bytes  Value
// 1      0x05
// 65     public key
// 1      key handle length
// *      key handle
// ASN.1  attestation certificate
// *      attestation signature

// https://hg.mozilla.org/mozilla-central/file/6d98cc745df58e544a8d71c131f060fc2c460d83/dom/webauthn/WebAuthnUtil.cpp#l285

fn asn1_seq_extractor(i: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    // Assert we have enough bytes for the ASN.1 header.
    if i.len() < 2 {
        return Err(nom::Err::Failure(nom::error::Error::new(
            i,
            nom::error::ErrorKind::LengthValue,
        )));
    }
    if i[0] != 0x30 {
        // It's not an ASN.1 sequence.
        return Err(nom::Err::Failure(nom::error::Error::new(
            i,
            nom::error::ErrorKind::IsNot,
        )));
    }

    let length: usize = if i[1] & 0x40 == 0x40 {
        // This is a long form length
        return Err(nom::Err::Failure(nom::error::Error::new(
            i,
            nom::error::ErrorKind::Tag,
        )));
    } else {
        i[1] as usize
    };

    if i.len() < (2 + length) {
        // Not enough bytes to satisfy.
        return Err(nom::Err::Failure(nom::error::Error::new(
            i,
            nom::error::ErrorKind::TakeUntil,
        )));
    }

    let (cert, rem) = i.split_at(2 + length);
    Ok((rem, cert))
}

named!( u2rd_parser<&[u8], U2FRegistrationData>,
    preceded!(
        verify!(take!(1), |val: &[u8]| val == &[0x05]),
        do_parse!(
            public_key_x: preceded!(
                verify!(take!(1), |val: &[u8]| val == &[0x04]),
                take!(32)
            ) >>
            public_key_y: take!(32) >>
            key_handle: length_data!(nom::number::complete::be_u8) >>
            att_cert: call!(asn1_seq_extractor) >>
            signature: call!(nom::combinator::rest) >>
            (U2FRegistrationData {
                public_key_x: public_key_x.to_vec(),
                public_key_y: public_key_y.to_vec(),
                key_handle: key_handle.to_vec(),
                att_cert: att_cert.to_vec(),
                signature: signature.to_vec(),
            })
        )
    )
);

impl TryFrom<&[u8]> for U2FRegistrationData {
    type Error = WebauthnCError;
    fn try_from(data: &[u8]) -> Result<U2FRegistrationData, WebauthnCError> {
        u2rd_parser(data)
            .map_err(|_| WebauthnCError::ParseNOMFailure)
            .map(|(_, ad)| ad)
    }
}

// https://hg.mozilla.org/mozilla-central/file/6d98cc745df58e544a8d71c131f060fc2c460d83/dom/webauthn/U2FHIDTokenManager.cpp#l296
// https://hg.mozilla.org/mozilla-central/file/6d98cc745df58e544a8d71c131f060fc2c460d83/dom/webauthn/WebAuthnUtil.cpp#l187

// A U2F Sign operation creates a signature over the "param" arguments (plus
// some other stuff) using the private key indicated in the key handle argument.
//
// The format of the signed data is as follows:
//
//  32    Application parameter
//  1     User presence (0x01)
//  4     Counter
//  32    Challenge parameter
//
// The format of the signature data is as follows:
//
//  1     User presence
//  4     Counter
//  *     Signature

named!( u2sd_sign_data_parser<&[u8], (u8, u32, Vec<u8>)>,
    do_parse!(
        up: call!(nom::number::complete::be_u8) >>
        cnt: u32!(nom::number::Endianness::Big) >>
        sig: call!(nom::combinator::rest) >>
        (
            (up, cnt, sig.to_vec())
        )
    )
);

impl U2FHid {
    pub fn new() -> Self {
        U2FHid {}
    }
}

impl U2FToken for U2FHid {
    // fn authenticator_make_credential(&self) -> {
    //          Invoke the authenticatorMakeCredential operation on authenticator with clientDataHash, options.rp, options.user, options.authenticatorSelection.requireResidentKey, userPresence, userVerification, credTypesAndPubKeyAlgs, excludeCredentialDescriptorList, and authenticatorExtensions as parameters.
    // }

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
            log::error!("User Verification not supported by attestation-rs");
            return Err(WebauthnCError::NotSupported);
        }

        let mut manager = AuthenticatorService::new().map_err(|e| {
            log::error!("Authentication Service -> {:?}", e);
            WebauthnCError::PlatformAuthenticator
        })?;

        manager.add_u2f_usb_hid_platform_transports();

        let mut flags = RegisterFlags::empty();

        if platform_attached {
            flags.insert(RegisterFlags::REQUIRE_PLATFORM_ATTACHMENT)
        }

        if resident_key {
            flags.insert(RegisterFlags::REQUIRE_RESIDENT_KEY)
        }

        log::debug!("flags -> {:?}", flags);

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (register_tx, register_rx) = channel();

        thread::spawn(move || loop {
            match status_rx.recv() {
                Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                    log::debug!("STATUS: device available: {}", dev_info);
                    log::info!(
                        "Available Device: {}",
                        std::str::from_utf8(&dev_info.device_name).unwrap_or("invalid device name")
                    );
                }
                Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                    log::debug!("STATUS: device unavailable: {}", dev_info)
                }
                Ok(StatusUpdate::Success { dev_info }) => {
                    log::info!("STATUS: success using device: {}", dev_info);
                }
                Err(_RecvError) => {
                    log::debug!("STATUS: end");
                    return;
                }
            }
        });

        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).unwrap();
        }));

        manager.register(
            flags,
            timeout_ms,
            chal_bytes,
            app_bytes,
            vec![],
            status_tx.clone(),
            callback,
        );

        let register_result = register_rx.recv().map_err(|e| {
            log::error!("Registration Channel Error -> {:?}", e);
            WebauthnCError::Internal
        })?;

        let (register_data, device_info) = register_result.map_err(|e| {
            log::error!("Device Registration Error -> {:?}", e);
            WebauthnCError::Internal
        })?;

        log::debug!("di ->  {:?}", device_info);

        // Now we have to transform the u2f response to something that
        // webauthn can understand.

        let u2rd = U2FRegistrationData::try_from(register_data.as_slice()).map_err(|e| {
            log::error!("U2F Registration Data Corrupt -> {:?}", e);
            e
        })?;

        log::debug!("u2rd -> {:?}", u2rd);
        Ok(u2rd)
    }

    // Then, using transport, invoke the authenticatorGetAssertion operation on authenticator, with rpId, clientDataHash, allowCredentialDescriptorList, userPresence, userVerification, and authenticatorExtensions as parameters.
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
            log::error!("User Verification not supported by attestation-rs");
            return Err(WebauthnCError::NotSupported);
        }

        let allowed_credentials: Vec<KeyHandle> = allowed_credentials
            .iter()
            .map(|ac| {
                KeyHandle {
                    // Dup the inner id.
                    credential: ac.id.0.clone(),
                    transports: AuthenticatorTransports::empty(),
                }
            })
            .collect();

        let mut manager = AuthenticatorService::new().map_err(|e| {
            log::error!("Authentication Service -> {:?}", e);
            WebauthnCError::PlatformAuthenticator
        })?;

        manager.add_u2f_usb_hid_platform_transports();

        let flags = SignFlags::empty();

        log::debug!("flags -> {:?}", flags);

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (register_tx, register_rx) = channel();

        thread::spawn(move || loop {
            match status_rx.recv() {
                Ok(StatusUpdate::DeviceAvailable { dev_info }) => {
                    log::debug!("STATUS: device available: {}", dev_info);
                    log::info!(
                        "Available Device: {}",
                        std::str::from_utf8(&dev_info.device_name).unwrap_or("invalid device name")
                    );
                }
                Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                    log::debug!("STATUS: device unavailable: {}", dev_info)
                }
                Ok(StatusUpdate::Success { dev_info }) => {
                    log::info!("STATUS: success using device: {}", dev_info);
                }
                Err(RecvError) => {
                    log::debug!("STATUS: end");
                    return;
                }
            }
        });

        let callback = StateCallback::new(Box::new(move |rv| {
            register_tx.send(rv).unwrap();
        }));

        manager.sign(
            flags,
            timeout_ms,
            chal_bytes,
            vec![app_bytes],
            allowed_credentials,
            status_tx.clone(),
            callback,
        );

        let register_result = register_rx.recv().map_err(|e| {
            log::error!("Registration Channel Error -> {:?}", e);
            WebauthnCError::Internal
        })?;

        let (appid, key_handle, sign_data, device_info) = register_result.map_err(|e| {
            log::error!("Device Registration Error -> {:?}", e);
            WebauthnCError::Internal
        })?;

        log::debug!("di ->  {:?}", device_info);

        let (_, (user_present, counter, signature)) =
            u2sd_sign_data_parser(sign_data.as_slice())
                .map_err(|_| WebauthnCError::ParseNOMFailure)?;

        Ok(U2FSignData {
            appid,
            key_handle,
            counter,
            signature,
            user_present,
        })
    }
}
