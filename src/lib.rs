
use crate::error::WebauthnCError;

use webauthn_rs::proto::{CreationChallengeResponse, RegisterPublicKeyCredential,
    RequestChallengeResponse, PublicKeyCredential, CollectedClientData,
    AuthenticatorAttachment, UserVerificationPolicy,
    AttestationObject
    };
use webauthn_rs::crypto::compute_sha256;
use url::Url;
use std::sync::mpsc::channel;
use std::thread;

use authenticator::{authenticatorservice::AuthenticatorService,
    RegisterFlags,
    statecallback::StateCallback,
    StatusUpdate,

    };

/*
use authenticator::{
    REQUIRE_RESIDENT_KEY,
    REQUIRE_USER_VERIFICATION,
    REQUIRE_PLATFORM_ATTACHMENT,
};
*/

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
        // This is rp.id
        appid: &str,
        // This is client_data_json_hash
        chal_bytes: Vec<u8>,
        // timeout from options
        timeout_ms: u64,
        // 
        platform_attached: bool,
        resident_key: bool,
        user_verification: bool,
    ) -> Result<(), WebauthnCError> {

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

        let app_bytes = compute_sha256(appid.as_bytes());

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

        log::debug!("rd -> {:?}", register_data);
        log::debug!("di -> {:?}", device_info);


        let ao = AttestationObject::try_from(rd).expect();
        log::debug!("ao -> {:?}", ao);


        Ok(())
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

        let r = self.perform_authenticator_u2f(
            &options.rp.id,
            client_data_json_hash.clone(),
            timeout.into(),
            platform_attached,
            resident_key,
            user_verification,
        )?;

        // Return a DOMException whose name is "NotAllowedError". In order to prevent information leak that could identify the user without consent, this step MUST NOT be executed before lifetimeTimer has expired. See §14.5 Registration Ceremony Privacy for details.

        Err(WebauthnCError::Unknown)
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

        println!("{:?}", chal);

        let wa = WebauthnAuthenticator::new();
        let r = wa.do_registration("https://localhost", chal)
            .map_err(|e| {
                eprintln!("Error -> {:?}", e);
                e
            })
            .expect("Failed to register");

        println!("{:?}", r);
    }
}
