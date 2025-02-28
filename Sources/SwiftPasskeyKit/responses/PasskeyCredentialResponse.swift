//
//  PasskeyCredentialResponse.swift
//
//
//  Created by Christian Rogobete on 22.02.25.
//

import Foundation

/// Response of a passkey creation request to be passed back to the passkey kit.
/// The values should be extratced from the original response. E.g. from ASAuthorizationPlatformPublicKeyCredentialRegistration
public class PasskeyCredentialResponse {

    public var credentialID:Data
    public var rawAttestationObject:Data
    
    public init(credentialID: Data, rawAttestationObject: Data) {
        self.credentialID = credentialID
        self.rawAttestationObject = rawAttestationObject
    }
}
