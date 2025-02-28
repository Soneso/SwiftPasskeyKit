//
//  PasskeyCredentialSigningResponse.swift
//
//
//  Created by Christian Rogobete on 25.02.25.
//

import Foundation

/// Response of a passkey assertion request to be passed back to the passkey kit.
/// The values should be extratced from the original response. E.g. from ASAuthorizationPlatformPublicKeyCredentialAssertion
public class PasskeyCredentialSigningResponse {
    
    public var credentialID:Data
    public var signature:Data
    public var authenticatorData:Data
    public var clientDataJSON:Data

    public init(credentialID: Data, signature: Data, authenticatorData: Data, clientDataJSON: Data) {
        self.credentialID = credentialID
        self.signature = signature
        self.authenticatorData = authenticatorData
        self.clientDataJSON = clientDataJSON
    }
}
