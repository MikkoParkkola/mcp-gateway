// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A client certificate identity built the way production builds one.

/// A real certificate's identity, through the checked parser.
pub fn cert_identity(
    common_name: Option<&str>,
    san_uri: Option<&str>,
) -> mcp_gateway::mtls::identity::CertIdentity {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(cn) = common_name {
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
    }
    if let Some(uri) = san_uri {
        params.subject_alt_names = vec![rcgen::SanType::URI(uri.try_into().expect("an ia5 uri"))];
    }
    let key = rcgen::KeyPair::generate().expect("key");
    let der = params
        .self_signed(&key)
        .expect("self-signed")
        .der()
        .to_vec();
    mcp_gateway::mtls::identity::CertIdentity::from_der(&der)
        .expect("parses")
        .expect("names someone")
}
