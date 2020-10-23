#[macro_use]
extern crate nom;

use crate::error::WebauthnCError;
    use webauthn_rs::base64_data::Base64UrlSafeData;

use webauthn_rs::proto::{CreationChallengeResponse, RegisterPublicKeyCredential,
    RequestChallengeResponse, PublicKeyCredential, CollectedClientData,
    AuthenticatorAttachment, UserVerificationPolicy,
    // AttestationObject
    AuthenticatorData,
    AuthenticatorAttestationResponseRaw,
    AttestationConveyancePreference
    };
use webauthn_rs::crypto::compute_sha256;
use url::Url;
use std::sync::mpsc::channel;
use std::thread;
use std::convert::TryFrom;
use std::collections::BTreeMap;
use serde_cbor::value::Value;
use std::iter;

use authenticator::{authenticatorservice::AuthenticatorService,
    RegisterFlags,
    statecallback::StateCallback,
    StatusUpdate,

    };


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

#[derive(Debug)]
struct U2FRegistrationData {
    public_key_x: Vec<u8>,
    public_key_y: Vec<u8>,
    key_handle: Vec<u8>,
    att_cert: Vec<u8>,
    signature: Vec<u8>
}

fn asn1_seq_extractor(i: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    // Assert we have enough bytes for the ASN.1 header.
    if i.len() < 2 {
        return Err(nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(1))))
    }
    if i[0] != 0x30 {
        // It's not an ASN.1 sequence.
        return Err(nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(2))))
    }

    let length: usize = if i[1] & 0x40 == 0x40 {
        // This is a long form length
        return Err(nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(3))))
    } else {
        i[1] as usize
    };

    if i.len() < (2 + length) {
        // Not enough bytes to satisfy.
        return Err(nom::Err::Failure(nom::Context::Code(i, nom::ErrorKind::Custom(4))))
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
            key_handle: length_data!(nom::be_u8) >>
            att_cert: call!(asn1_seq_extractor) >>
            signature: call!(nom::rest) >>
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


/*
use authenticator::{
    REQUIRE_RESIDENT_KEY,
    REQUIRE_USER_VERIFICATION,
    REQUIRE_PLATFORM_ATTACHMENT,
};
*/

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

pub mod error;

pub struct WebauthnAuthenticator {
}

impl WebauthnAuthenticator {
    pub fn new() -> Self {
        WebauthnAuthenticator {
        }
    }

    // fn authenticator_make_credential(&self) -> {
        //          Invoke the authenticatorMakeCredential operation on authenticator with clientDataHash, options.rp, options.user, options.authenticatorSelection.requireResidentKey, userPresence, userVerification, credTypesAndPubKeyAlgs, excludeCredentialDescriptorList, and authenticatorExtensions as parameters.
    // }

    fn perform_authenticator_u2f(&self,
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

        let mut manager = AuthenticatorService::new()
            .map_err(|e| {
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
                    log::info!("STATUS: device available: {}", dev_info)
                }
                Ok(StatusUpdate::DeviceUnavailable { dev_info }) => {
                    log::error!("STATUS: device unavailable: {}", dev_info)
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

        manager.register(
            flags,
            timeout_ms,
            chal_bytes,
            app_bytes,
            vec![],
            status_tx.clone(),
            callback
        );

        let register_result = register_rx.recv()
            .map_err(|e| {
                log::error!("Registration Channel Error -> {:?}", e);
                WebauthnCError::Internal
            })
            ?;

        let (register_data, device_info) = register_result
            .map_err(|e| {
                log::error!("Device Registration Error -> {:?}", e);
                WebauthnCError::Internal
            })
            ?;

        log::debug!("di ->  {:?}", device_info);

        // Now we have to transform the u2f response to something that
        // webauthn can understand.

        let u2rd = U2FRegistrationData::try_from(register_data.as_slice())
            .map_err(|e| {
                log::error!("U2F Registration Data Corrupt -> {:?}", e);
                e
            })
            ?;

        log::debug!("u2rd -> {:?}", u2rd);
        Ok(u2rd)
    }

    /// 5.1.3. Create a New Credential - PublicKeyCredential’s [[Create]](origin, options, sameOriginWithAncestors) Method
    /// https://www.w3.org/TR/webauthn/#createCredential
    ///
    /// 6.3.2. The authenticatorMakeCredential Operation
    /// https://www.w3.org/TR/webauthn/#op-make-cred
    pub fn do_registration(&self,
        origin: &str,
        options: CreationChallengeResponse,
        // _same_origin_with_ancestors: bool,
        ) -> Result<RegisterPublicKeyCredential, WebauthnCError> {
        // Assert: options.publicKey is present.
        // This is asserted through rust types.

        // If sameOriginWithAncestors is false, return a "NotAllowedError" DOMException.
        // We just don't take this value.

        // Let options be the value of options.publicKey.
        let options = &options.public_key;

        // If the timeout member of options is present, check if its value lies within a reasonable range as defined by the client and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this adjusted value. If the timeout member of options is not present, then set lifetimeTimer to a client-specific default.
        let timeout = options.timeout
            .map(|t| {
                if t > 60000 {
                    60000
                } else {
                    t
                }
            })
            .unwrap_or(60000);

        // Let callerOrigin be origin. If callerOrigin is an opaque origin, return a DOMException whose name is "NotAllowedError", and terminate this algorithm.
        // This is a bit unclear - see https://github.com/w3c/wpub/issues/321.
        // It may be a browser specific quirk.
        // https://html.spec.whatwg.org/multipage/origin.html
        // As a result we don't need to check for our needs.

        // Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then return a DOMException whose name is "Security" and terminate this algorithm.
        let caller_origin = Url::parse(origin)
            .map_err(|pe| {
                log::error!("url parse failure -> {:?}", pe);
                WebauthnCError::Security
            })?
        ;

        let effective_domain = caller_origin.domain()
            // Checking by IP today muddies things. We'd need a check for rp.id about suffixes
            // to be different for this.
            // .or_else(|| caller_origin.host_str())
            .ok_or(WebauthnCError::Security)
            .map_err(|e| {
                log::error!("origin has no domain or host_str");
                e
            })?;

        log::debug!("effective domain -> {:?}", effective_domain);

        // If options.rp.id
        //      Is present
        //          If options.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, return a DOMException whose name is "Security", and terminate this algorithm.
        //      Is not present
        //          Set options.rp.id to effectiveDomain.

        if !effective_domain.ends_with(&options.rp.id) {
            log::error!("relying party id domain is not suffix of effective domain.");
            return Err(WebauthnCError::Security);
        }

        // Check origin is https:// if effectiveDomain != localhost.
        if !(effective_domain == "localhost" || caller_origin.scheme() == "https") {
            log::error!("An insecure domain or scheme in origin. Must be localhost or https://");
            return Err(WebauthnCError::Security);
        }

        // Let credTypesAndPubKeyAlgs be a new list whose items are pairs of PublicKeyCredentialType and a COSEAlgorithmIdentifier.
        // Done in rust types.

        // For each current of options.pubKeyCredParams:
        //     If current.type does not contain a PublicKeyCredentialType supported by this implementation, then continue.
        //     Let alg be current.alg.
        //     Append the pair of current.type and alg to credTypesAndPubKeyAlgs.
        let cred_types_and_pub_key_algs: Vec<_> = options.pub_key_cred_params.iter()
            .filter_map(|param| {
                if param.type_ != "public-key" {
                    None
                } else {
                    Some((param.type_.clone(), param.alg))
                }
            })
            .collect();

        log::debug!("Found -> {:?}", cred_types_and_pub_key_algs);

        // If credTypesAndPubKeyAlgs is empty and options.pubKeyCredParams is not empty, return a DOMException whose name is "NotSupportedError", and terminate this algorithm.
        if cred_types_and_pub_key_algs.is_empty() {
            return Err(WebauthnCError::NotSupported)
        }

        // Webauthn-rs doesn't support this yet.
        /*
            // Let clientExtensions be a new map and let authenticatorExtensions be a new map.

            // If the extensions member of options is present, then for each extensionId → clientExtensionInput of options.extensions:
            //     If extensionId is not supported by this client platform or is not a registration extension, then continue.
            //     Set clientExtensions[extensionId] to clientExtensionInput.
            //     If extensionId is not an authenticator extension, then continue.
            //     Let authenticatorExtensionInput be the (CBOR) result of running extensionId’s client extension processing algorithm on clientExtensionInput. If the algorithm returned an error, continue.
            //     Set authenticatorExtensions[extensionId] to the base64url encoding of authenticatorExtensionInput.
        */

        // Let collectedClientData be a new CollectedClientData instance whose fields are:
        //    type
        //        The string "webauthn.create".
        //    challenge
        //        The base64url encoding of options.challenge.
        //    origin
        //        The serialization of callerOrigin.

        //    Not Supported Yet.
        //    tokenBinding
        //        The status of Token Binding between the client and the callerOrigin, as well as the Token Binding ID associated with callerOrigin, if one is available.
        let collected_client_data = CollectedClientData {
            type_: "webauthn.create".to_string(),
            challenge: options.challenge.clone(),
            origin: caller_origin.as_str().to_string(),
            token_binding: None,
        };

        //  Let clientDataJSON be the JSON-serialized client data constructed from collectedClientData.
        let client_data_json = serde_json::to_string(&collected_client_data)
            .map_err(|_| WebauthnCError::JSON)?;

        // Let clientDataHash be the hash of the serialized client data represented by clientDataJSON.
        let client_data_json_hash = compute_sha256(client_data_json.as_bytes());

        log::debug!("client_data_json -> {:?}", client_data_json);
        log::debug!("client_data_json_hash -> {:?}", client_data_json_hash);

        // Not required.
        // If the options.signal is present and its aborted flag is set to true, return a DOMException whose name is "AbortError" and terminate this algorithm.

        // Let issuedRequests be a new ordered set.

        // Let authenticators represent a value which at any given instant is a set of client platform-specific handles, where each item identifies an authenticator presently available on this client platform at that instant.

        // Start lifetimeTimer.

        // While lifetimeTimer has not expired, perform the following actions depending upon lifetimeTimer, and the state and response for each authenticator in authenticators:

        //    If lifetimeTimer expires,
        //        For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests.

        //    If the user exercises a user agent user-interface option to cancel the process,
        //        For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests. Return a DOMException whose name is "NotAllowedError".

        //    If the options.signal is present and its aborted flag is set to true,
        //        For each authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove authenticator from issuedRequests. Then return a DOMException whose name is "AbortError" and terminate this algorithm.

        //    If an authenticator becomes available on this client device,
        //         If options.authenticatorSelection is present:
        //             If options.authenticatorSelection.authenticatorAttachment is present and its value is not equal to authenticator’s authenticator attachment modality, continue.
        //             If options.authenticatorSelection.requireResidentKey is set to true and the authenticator is not capable of storing a client-side-resident public key credential source, continue.
        //             If options.authenticatorSelection.userVerification is set to required and the authenticator is not capable of performing user verification, continue.
        //          Let userVerification be the effective user verification requirement for credential creation, a Boolean value, as follows. If options.authenticatorSelection.userVerification
        //              is set to required -> Let userVerification be true.
        //              is set to preferred
        //                  If the authenticator
        //                      is capable of user verification -> Let userVerification be true.
        //                      is not capable of user verification -> Let userVerification be false.
        //              is set to discouraged -> Let userVerification be false.
        //          Let userPresence be a Boolean value set to the inverse of userVerification.
        //          Let excludeCredentialDescriptorList be a new list.
        //          For each credential descriptor C in options.excludeCredentials:
        //              If C.transports is not empty, and authenticator is connected over a transport not mentioned in C.transports, the client MAY continue.
        //              Otherwise, Append C to excludeCredentialDescriptorList.
        //          Invoke the authenticatorMakeCredential operation on authenticator with clientDataHash, options.rp, options.user, options.authenticatorSelection.requireResidentKey, userPresence, userVerification, credTypesAndPubKeyAlgs, excludeCredentialDescriptorList, and authenticatorExtensions as parameters.

        //          Append authenticator to issuedRequests.

        //    If an authenticator ceases to be available on this client device,
        //         Remove authenticator from issuedRequests.
        
        //    If any authenticator returns a status indicating that the user cancelled the operation,
        //         Remove authenticator from issuedRequests.
        //         For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.

        //    If any authenticator returns an error status equivalent to "InvalidStateError",
        //         Remove authenticator from issuedRequests.
        //         For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
        //         Return a DOMException whose name is "InvalidStateError" and terminate this algorithm.

        //    If any authenticator returns an error status not equivalent to "InvalidStateError",
        //         Remove authenticator from issuedRequests.

        //    If any authenticator indicates success,
        //         Remove authenticator from issuedRequests.
        //         Let credentialCreationData be a struct whose items are:
        //         Let constructCredentialAlg be an algorithm that takes a global object global, and whose steps are:

        //         Let attestationObject be a new ArrayBuffer, created using global’s %ArrayBuffer%, containing the bytes of credentialCreationData.attestationObjectResult’s value.


        //         Let id be attestationObject.authData.attestedCredentialData.credentialId.
        //         Let pubKeyCred be a new PublicKeyCredential object associated with global whose fields are:
        //         For each remaining authenticator in issuedRequests invoke the authenticatorCancel operation on authenticator and remove it from issuedRequests.
        //         Return constructCredentialAlg and terminate this algorithm.


        // For our needs, we let the u2f auth library handle the above, but currently it can't accept
        // verified devices for u2f with ctap1/2. We may need to change u2f/authenticator library in the future.
        // As a result this really limits our usage to certain device classes. This is why we implement
        // this section in a seperate function call.

        let (platform_attached, resident_key, user_verification) = match &options.authenticator_selection {
            Some(auth_sel) => {

                let pa = auth_sel.authenticator_attachment.as_ref().map(|v| {
                    v == &AuthenticatorAttachment::Platform
                })
                .unwrap_or(false);
                let uv = &auth_sel.user_verification == &UserVerificationPolicy::Required;
                (pa, auth_sel.require_resident_key, uv)
            }
            None => {
                (false, false, false)
            }
        };

        let rp_id_hash = compute_sha256(options.rp.id.as_bytes());

        let u2rd = self.perform_authenticator_u2f(
            rp_id_hash.clone(),
            client_data_json_hash,
            timeout.into(),
            platform_attached,
            resident_key,
            user_verification,
        )?;

        // From the u2f response, we now need to assemble the attestation object now.

        // cbor encode the public key. We already decomposed this, so just create
        // the correct bytes.
        let mut map = BTreeMap::new();
        // KeyType -> EC2
        map.insert(Value::Integer(1), Value::Integer(2));
        // Alg -> ES256
        map.insert(Value::Integer(3), Value::Integer(-7));

        // Curve -> P-256
        map.insert(Value::Integer(-1), Value::Integer(1));
        // EC X coord
        map.insert(Value::Integer(-2), Value::Bytes(u2rd.public_key_x));
        // EC Y coord
        map.insert(Value::Integer(-3), Value::Bytes(u2rd.public_key_y));

        let pk_cbor = Value::Map(map);
        let pk_cbor_bytes = serde_cbor::to_vec(&pk_cbor)
            .map_err(|e| {
                log::error!("PK CBOR -> {:?}", e);
                WebauthnCError::CBOR
            })?;

        let key_handle_len: u16 = u16::try_from(u2rd.key_handle.len())
            .map_err(|e| {
                log::error!("CBOR kh len is not u16 -> {:?}", e);
                WebauthnCError::CBOR
            })?;

        // combine aaGuid, KeyHandle, CborPubKey into a AttestedCredentialData. (acd)
        let aaguid: [u8; 16] = [0; 16];

        let acd: Vec<u8> = 
            // make a 00 aaguid
            aaguid.iter()
                .chain(
                    key_handle_len.to_be_bytes().iter()
                )
                .map(|v| *v)
                .chain(u2rd.key_handle.iter().map(|v| *v))
                .chain(pk_cbor_bytes.iter().map(|v| *v))
                .collect();

        // set counter to 0 during create
        // Combine rp_id_hash, flags, counter, acd, into authenticator data.
        // The flags are always user_present, att present
        let flags = 0b01000001;

        let authdata: Vec<u8> = 
            rp_id_hash.iter().map(|v| *v)
            .chain(
                iter::once(flags)
            )
            .chain(
                // A 0 u32 counter
                iter::repeat(0).take(4)
            )
            .chain(acd.into_iter())
            .collect();

        let mut attest_map = BTreeMap::new();

        match options.attestation {
            None | Some(AttestationConveyancePreference::None)  => {
                attest_map.insert(
                    Value::Text("fmt".to_string()),
                    Value::Text("none".to_string()),
                );
                attest_map.insert(
                    Value::Text("attStmt".to_string()),
                    Value::Null
                );
                attest_map.insert(
                    Value::Text("authData".to_string()),
                    Value::Bytes(authdata)
                );
            }
            _ => {
            //    create a u2f attestation from authData, attest cert, a signature,)
                unimplemented!();
            }
        }

        let ao = Value::Map(attest_map);

        let ao_bytes = serde_cbor::to_vec(&ao)
            .map_err(|e| {
                log::error!("AO CBOR -> {:?}", e);
                WebauthnCError::CBOR
            })?;

        // Return a DOMException whose name is "NotAllowedError". In order to prevent information leak that could identify the user without consent, this step MUST NOT be executed before lifetimeTimer has expired. See §14.5 Registration Ceremony Privacy for details.

        let id: String = Base64UrlSafeData(u2rd.key_handle.clone()).to_string();

        let rego = RegisterPublicKeyCredential {
            id,
            raw_id: Base64UrlSafeData(u2rd.key_handle.clone()),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: Base64UrlSafeData(ao_bytes),
                client_data_json: Base64UrlSafeData(
                    client_data_json.as_bytes().to_vec()
                )
            },
            type_: "public-key".to_string()
        };

        log::debug!("rego  -> {:?}", rego);
        Ok(rego)
    }

    pub fn do_authentication(&self, chal: RequestChallengeResponse) -> Result<PublicKeyCredential, WebauthnCError> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use crate::WebauthnAuthenticator;
    use webauthn_rs::proto::*;
    use webauthn_rs::base64_data::Base64UrlSafeData;
    pub const CHALLENGE_SIZE_BYTES: usize = 32;

    #[test]
    fn webauthn_authenticator_basic_registration() {
        let _ = env_logger::builder().is_test(true).try_init();
        let chal = CreationChallengeResponse {
            public_key: PublicKeyCredentialCreationOptions {
                rp: RelyingParty {
                    name: "WebauthenAuthticatorRs".to_string(),
                    id: "localhost".to_string(),
                },
                user: User {
                    id: Base64UrlSafeData(
                        base64::decode("d2lsbGlhbQ==").unwrap()
                    ),
                    name: "william".to_string(),
                    display_name: "William".to_string(),
                },
                challenge: Base64UrlSafeData(
                    (0..CHALLENGE_SIZE_BYTES).map(|_| 0).collect::<Vec<u8>>()
                ),
                pub_key_cred_params: vec![
                    PubKeyCredParams {
                        type_: "public-key".to_string(),
                        alg: -7,
                    }
                ],
                timeout: Some(60000),
                attestation: Some(AttestationConveyancePreference::None),
                exclude_credentials: None,
                authenticator_selection: Some(AuthenticatorSelectionCriteria{
                    authenticator_attachment: None,
                    require_resident_key: false,
                    user_verification: UserVerificationPolicy::Discouraged,
                }),
                extensions: None,
            }
        };

        let wa = WebauthnAuthenticator::new();
        let r = wa.do_registration("https://localhost", chal)
            .map_err(|e| {
                eprintln!("Error -> {:?}", e);
                e
            })
            .expect("Failed to register");

    }
}
