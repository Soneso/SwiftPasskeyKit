//
//  PasskeySignature.swift
//
//
//  Created by Christian Rogobete on 22.02.25.
//

import Foundation
import stellarsdk

public protocol PasskeySignature {
    func toSCValXDR() -> SCValXDR
}

public class Secp256r1Signature:PasskeySignature {
    public var authenticatorData:Data
    public var clientDataJson:Data
    public var signature:Data
    
    public init(authenticatorData:Data, clientDataJson:Data, signature:Data) {
        self.authenticatorData = authenticatorData
        self.clientDataJson = clientDataJson
        self.signature = signature
    }
    
    public func toSCValXDR() -> stellarsdk.SCValXDR {
        return SCValXDR.vec([SCValXDR.symbol("Secp256r1"),
                             SCValXDR.map([
                                SCMapEntryXDR(key: SCValXDR.symbol("authenticator_data"),
                                              val: SCValXDR.bytes(authenticatorData)),
                                SCMapEntryXDR(key: SCValXDR.symbol("client_data_json"),
                                              val: SCValXDR.bytes(clientDataJson)),
                                SCMapEntryXDR(key: SCValXDR.symbol("signature"),
                                              val: SCValXDR.bytes(signature)),
                             ])
                            ])
    }
}

public class Ed25519Signature:PasskeySignature {
    public var signature:Data
    
    public init(signature:Data) {
        self.signature = signature
    }
    
    public func toSCValXDR() -> stellarsdk.SCValXDR {
        return SCValXDR.vec([SCValXDR.symbol("Ed25519"),SCValXDR.bytes(signature)])
    }
}

public class PolicySignature:PasskeySignature {
    
    public func toSCValXDR() -> stellarsdk.SCValXDR {
        return SCValXDR.vec([SCValXDR.symbol("Policy")])
    }
}
