//
//  CreateWalletResponse.swift
//
//
//  Created by Christian Rogobete on 21.02.25.
//

import Foundation
import stellarsdk

public class CreateWalletResponse {
    /// keyId identifying the user/signer by their passkey credentials
    public var keyId:Data
    
    /// Derived contract id of the new wallet that can be created.
    public var contractId:String
    
    /// The transaction that creates the smart wallet if sent to stellar/soroban.
    public var transaction:Transaction
    
    public init(keyId:Data, contractId:String, transaction:Transaction) {
        self.keyId = keyId
        self.contractId = contractId
        self.transaction = transaction
    }
    
}
