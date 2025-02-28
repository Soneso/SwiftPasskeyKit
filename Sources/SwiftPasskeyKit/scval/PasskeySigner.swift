//
//  PasskeySigner.swift
//
//
//  Created by Christian Rogobete on 22.02.25.
//

import Foundation
import stellarsdk

public class PasskeySigner {
    var type:PasskeySignerType
    var expiration:UInt32?
    var limits:[PasskeyAddressLimits]?
    var storage: PasskeySignerStorage?
    
    internal init(type: PasskeySignerType, expiration: UInt32? = nil, limits: [PasskeyAddressLimits]? = nil, storage: PasskeySignerStorage? = nil) {
        self.type = type
        self.expiration = expiration
        self.limits = limits
        self.storage = storage
    }
    
    internal func signerArgs() ->  [SCValXDR] {
        var args:[SCValXDR] = []
        
        if let expiration = self.expiration {
            args.append(SCValXDR.vec([SCValXDR.u32(expiration)]))
        } else {
            args.append(SCValXDR.vec([SCValXDR.void]))
        }
        
        if let limits = self.limits {
            var mapEntries:[SCMapEntryXDR] = []
            for entry in limits {
                if let signerKeys = entry.limits {
                    var elements:[SCValXDR] = []
                    for signerKey in signerKeys {
                        elements.append(signerKey.toSCValXDR())
                    }
                    mapEntries.append(SCMapEntryXDR(key: SCValXDR.address(entry.address),
                                                    val: SCValXDR.vec(elements)))
                } else {
                    mapEntries.append(SCMapEntryXDR(key: SCValXDR.address(entry.address),
                                                    val: SCValXDR.void))
                }
            }
            args.append(SCValXDR.vec([SCValXDR.map(mapEntries)]))
        } else {
            args.append(SCValXDR.vec([SCValXDR.void]))
        }
        
        if let storage = storage {
            args.append(SCValXDR.vec([SCValXDR.symbol(storage.rawValue)]))
        } else {
            args.append(SCValXDR.vec([SCValXDR.void]))
        }
        return args
    }
    
    public func toSCValXDR() -> SCValXDR {
        return SCValXDR.vec(signerArgs())
    }
}

public class PasskeyAddressLimits {
    public var address:SCAddressXDR
    public var limits:[PasskeySignerKey]?
    
    public init(address:SCAddressXDR, limits:[PasskeySignerKey]?) {
        self.address = address
        self.limits = limits
    }
}

public class PolicyPasskeySigner: PasskeySigner {
    public var policyAddress:SCAddressXDR
    
    public init (policyAddress: SCAddressXDR, expiration: UInt32? = nil, limits: [PasskeyAddressLimits]? = nil, storage: PasskeySignerStorage? = nil) {
        
        self.policyAddress = policyAddress
        
        super.init(type: PasskeySignerType.policy,
                   expiration: expiration,
                   limits: limits,
                   storage: storage)
    }
    
    public override func toSCValXDR() -> SCValXDR {
        var elements:[SCValXDR] = []
        elements.append(SCValXDR.symbol(type.rawValue))
        elements.append(SCValXDR.address(policyAddress))
        elements.append(contentsOf: signerArgs())
        return SCValXDR.vec(elements)
    }
}

public class Ed25519PasskeySigner: PasskeySigner {
    public var publicKey:Data
    
    public init (publicKey: Data, expiration: UInt32? = nil, limits: [PasskeyAddressLimits]? = nil, storage: PasskeySignerStorage? = nil) {
        
        self.publicKey = publicKey
        
        super.init(type: PasskeySignerType.ed25519,
                   expiration: expiration,
                   limits: limits,
                   storage: storage)
    }
    
    public override func toSCValXDR() -> SCValXDR {
        var elements:[SCValXDR] = []
        elements.append(SCValXDR.symbol(type.rawValue))
        elements.append(SCValXDR.bytes(publicKey))
        elements.append(contentsOf: signerArgs())
        return SCValXDR.vec(elements)
    }
}

public class Secp256r1PasskeySigner: PasskeySigner {
    public var keyId:Data
    public var publicKey:Data
    
    public init (keyId: Data, publicKey: Data, expiration: UInt32? = nil, limits: [PasskeyAddressLimits]? = nil, storage: PasskeySignerStorage? = nil) {
        
        self.keyId = keyId
        self.publicKey = publicKey
        
        super.init(type: PasskeySignerType.secp256r1,
                   expiration: expiration,
                   limits: limits,
                   storage: storage)
    }
    
    public override func toSCValXDR() -> SCValXDR {
        var elements:[SCValXDR] = []
        elements.append(SCValXDR.symbol(type.rawValue))
        elements.append(SCValXDR.bytes(keyId))
        elements.append(SCValXDR.bytes(publicKey))
        elements.append(contentsOf: signerArgs())
        return SCValXDR.vec(elements)
    }
}

public enum PasskeySignerType:String {
    case policy = "Policy"
    case ed25519 = "Ed25519"
    case secp256r1 = "Secp256r1"
}

public enum PasskeySignerStorage:String {
    case persistent = "Persistent"
    case temporary = "Temporary"
}

public protocol PasskeySignerKey {
    var type:PasskeySignerType {get}
    func toSCValXDR() -> SCValXDR
}

public class PolicyPasskeySignerKey : PasskeySignerKey {
    public var type: PasskeySignerType
    public var policyAddress: SCAddressXDR
    
    public init(policyAddress: SCAddressXDR) {
        self.type = PasskeySignerType.policy
        self.policyAddress = policyAddress
    }
    
    public func toSCValXDR() -> stellarsdk.SCValXDR {
        SCValXDR.vec([SCValXDR.symbol(type.rawValue), SCValXDR.address(policyAddress)])
    }
}

public class Ed25519PasskeySignerKey : PasskeySignerKey {
    public var type: PasskeySignerType
    public var publicKey: Data
    
    public init(publicKey: Data) {
        self.type = PasskeySignerType.ed25519
        self.publicKey = publicKey
    }
    
    public func toSCValXDR() -> stellarsdk.SCValXDR {
        SCValXDR.vec([SCValXDR.symbol(type.rawValue), SCValXDR.bytes(publicKey)])
    }
}

public class Secp256r1PasskeySignerKey : PasskeySignerKey {
    public var type: PasskeySignerType
    public var keyId: Data
    
    public init(keyId: Data) {
        self.type = PasskeySignerType.secp256r1
        self.keyId = keyId
    }
    
    public func toSCValXDR() -> stellarsdk.SCValXDR {
        SCValXDR.vec([SCValXDR.symbol(type.rawValue), SCValXDR.bytes(keyId)])
    }
}
