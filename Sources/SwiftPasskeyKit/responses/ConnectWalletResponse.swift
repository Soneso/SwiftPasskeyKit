//
//  ConnectWalletResponse.swift
//
//
//  Created by Christian Rogobete on 21.02.25.
//

import Foundation

public class ConnectWalletResponse {
    /// keyId identifying the user/signer by their passkey credentials
    public var keyId:Data
    
    /// Contract id of the connected wallet.
    public var contractId:String
    
    public init(keyId:Data, contractId:String) {
        self.keyId = keyId
        self.contractId = contractId
    }
    
}
