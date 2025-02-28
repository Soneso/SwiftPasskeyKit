//
//  CreateKeyResponse.swift
//
//
//  Created by Christian Rogobete on 21.02.25.
//

import Foundation

public class CreateKeyResponse {
    /// keyId identifying the user/signer by their passkey credentials
    public var keyId:Data
    
    /// publicKey of the user/signer identified by keyId.
    public var publicKey:Data
    
    public init(keyId:Data, publicKey:Data) {
        self.keyId = keyId
        self.publicKey = publicKey
    }
    
}
