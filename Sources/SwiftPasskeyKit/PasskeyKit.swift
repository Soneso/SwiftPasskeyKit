//
//  File.swift
//
//
//  Created by Christian Rogobete on 21.02.25.
//

import Foundation
import stellarsdk

public class PasskeyKit {
    public var rpId:String
    public var rpcUrl:String
    public var wasmHash:String
    public var network:Network
    public var keyId:Data?
    public var walletKeyPair:KeyPair
    public var server:SorobanServer
    private var challenge = "stellaristhebetterblockchain".data(using: .utf8)!
    
    /// Constructor.
    ///
    /// - Parameters:
    ///   - rpId: The domain where your AASA file is deployed. E.g. "soneso.com"
    ///   - rpcUrl: The url to the soroban rpc server to be used for requests
    ///   - wasmHash: The hash of your installed smart wallet contract
    ///   - network: Stellar Network to be used.
    ///
    public init(rpId:String,
                rpcUrl:String,
                wasmHash:String,
                network:Network) {
        self.rpId = rpId
        self.rpcUrl = rpcUrl
        self.wasmHash = wasmHash
        self.network = network
        self.server = SorobanServer(endpoint: rpcUrl)
        self.server.enableLogging = true
        self.walletKeyPair = KeyPair(seed: try! Seed(bytes: [UInt8](network.networkId)))
    }
    
    /// Returns a [CreateWalletResponse] containing the data needed to create a new wallet for the given [userName].
    /// This includes the transaction to be submitted by you to the stellar network, so that the wallet is created.
    /// When calling this function you must provide a [createCredentials] function that requests the creation and returns the
    /// users passkey credentials.
    ///
    /// This function will use it's own source account and you will receive an already signed transaction that you
    /// can send to Stellar via a fee bump transaction or to launchtube (https://github.com/stellar/launchtube).
    ///
    /// - Parameters:
    ///   - userName: Username that will be used for creating the passkey credentials
    ///   - createCredentials: Function that requests the creation and returns the users passkey credentials.
    ///
    public func createWallet(userName:String, createCredentials:((_ userName:String, _ userId:Data, _ challenge:Data, _ rpId:String) async throws -> PasskeyCredentialResponse)) async throws -> CreateWalletResponse {
        
        let key = try await createKey(userName: userName, createCredentials: createCredentials)
        let transaction = try await createAndSignDeployTx(keyId: key.keyId,
                                                          publicKey: key.publicKey)
        let contractId = try deriveContractId(keyId: key.keyId)
        return CreateWalletResponse(keyId: key.keyId, contractId: contractId, transaction: transaction)
        
    }
    
    /// This function connects your passkey kit instance to the users wallet if it exists.
    /// If you provide the [keyId] of the user, then this function will only check if the wallet exists
    /// and connect it. If you provide no [keyId] you must provide the [passkeySignIn] function that requests and returns the
    /// users passkey login credentials.
    ///
    /// - Parameters:
    ///   - keyId: Optional. Credentials id of the user (received from [createWallet])
    ///   - passkeySignIn: Optional. Function that requests and returns the users passkey login credentials.
    ///
    public func connectWallet(keyId:Data? = nil, passkeySignIn:((_ challenge:Data, _ rpId:String) async throws -> Data)? = nil) async throws -> ConnectWalletResponse {
        
        if (keyId == nil && passkeySignIn == nil) {
            throw PasskeyKitError.runtimeError("One of keyId or passkeySignIn must be given")
        }
        
        var contractId:String?
        var newKeyId:Data?
        
        if let keyId = keyId {
            contractId = try deriveContractId(keyId: keyId)
            newKeyId = keyId
        } else {
            newKeyId = try await passkeySignIn!(challenge, rpId)
            contractId = try deriveContractId(keyId: newKeyId!)
        }
        
        let contractDataResponse = await server.getContractData(contractId: contractId!,
                                                                key: SCValXDR.ledgerKeyContractInstance,
                                                                durability: ContractDataDurability.persistent)
        switch contractDataResponse {
        case .success(_):
            self.keyId = newKeyId!
            return ConnectWalletResponse(keyId: newKeyId!, contractId: contractId!)
        case .failure(let error):
            throw error
        }
    }
    
    /// This function creates a new key (keyId + publicKey), that can be used as a Secp256r1 signer for your wallet.
    /// Provide the [userName] to create the new key for. You must also provide
    /// a [createCredentials] function, that requests the creation and returns the
    /// users passkey credentials.
    ///
    /// - Parameters:
    ///   - userName: Username that will be used for creating the passkey credentials
    ///   - passkeySignIn: Function that requests the creation and returns the users passkey credentials.
    ///
    public func createKey(userName:String, createCredentials:((_ userName:String, _ userId:Data, _ challenge:Data, _ rpId:String) async throws -> PasskeyCredentialResponse)) async throws -> CreateKeyResponse {
        
        let dateFormatter = DateFormatter.posixFormatter
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        
        let displayName = "\(userName) - \(dateFormatter.string(from: Date()))"
        let userId = Data(base64Encoded: displayName.base64Encoded()!)!
        let credentialCreationResponse = try await createCredentials(displayName, userId, challenge, rpId)
        let publicKey = try await getPublicKey(rawAttestationObject:credentialCreationResponse.rawAttestationObject)
        return CreateKeyResponse(keyId: credentialCreationResponse.credentialID, publicKey: publicKey)
    }
    
    /// Creates a transaction that adds a new secp256r1 signer to the wallet,
    /// identified by [keyId] and [publicKey] that can be obtained by calling [createKey].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - keyId: KeyId of the signer to be added (see also [createKey])
    ///   - publicKey: Public key of the signer to be added (see also [createKey])
    ///   - limits: Optional. Limits to be applied to the signer (e.g. policy)
    ///   - storage: Optional. Storage type for the signer (e.g. temporary, persistent). If not provided, persistent will be used.
    ///   - expiration: Optional. Sequence number of the ledger at wich the signer should expire.
    ///
    public func addSecp256r1(txSourceAccountId:String,
                             keyId:Data,
                             publicKey:Data,
                             limits:[PasskeyAddressLimits]? = nil,
                             storage:PasskeySignerStorage? = nil,
                             expiration:UInt32? = nil) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        let signer = Secp256r1PasskeySigner(keyId: keyId,
                                            publicKey: publicKey,
                                            expiration: expiration,
                                            limits: limits,
                                            storage: storage)
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "add_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Creates a transaction that updates the secp256r1 signer of the wallet,
    /// identified by [keyId] and [publicKey].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - keyId: KeyId of the signer to be updated (see also [createKey])
    ///   - publicKey: Public key of the signer to be updated (see also [createKey])
    ///   - limits: Optional. Limits to be applied to the signer (e.g. policy)
    ///   - storage: Optional. Storage type for the signer (e.g. temporary, persistent).
    ///   - expiration: Optional. Sequence number of the ledger at wich the signer should expire.
    ///
    public func updateSecp256r1(txSourceAccountId:String,
                                keyId:Data,
                                publicKey:Data,
                                limits:[PasskeyAddressLimits]? = nil,
                                storage:PasskeySignerStorage? = nil,
                                expiration:UInt32? = nil) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        
        let signer = Secp256r1PasskeySigner(keyId: keyId,
                                            publicKey: publicKey,
                                            expiration: expiration,
                                            limits: limits,
                                            storage: storage)
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "update_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Creates a transaction that removes the secp256r1 signer of the wallet,
    /// identified by [keyId] and [publicKey].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - keyId: KeyId of the signer to be removed (see also [createKey])
    ///   - publicKey: Public key of the signer to be removed (see also [createKey])
    ///
    public func removeSecp256r1(txSourceAccountId:String,
                                keyId:Data,
                                publicKey:Data) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        let signer = Secp256r1PasskeySigner(keyId: keyId, publicKey: publicKey)
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "remove_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Creates a transaction that adds a new ed25519 signer to the wallet,
    /// identified by [newSignerAccountId].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - newSignerAccountId: Stellar account id of the signer to be added
    ///   - limits: Optional. Limits to be applied to the signer (e.g. policy)
    ///   - storage: Optional. Storage type for the signer (e.g. temporary, persistent).
    ///   - expiration: Optional. Sequence number of the ledger at wich the signer should expire.
    ///
    public func addEd25519(txSourceAccountId:String,
                           newSignerAccountId:String,
                           limits:[PasskeyAddressLimits]? = nil,
                           storage:PasskeySignerStorage? = nil,
                           expiration:UInt32? = nil) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        let kp = try KeyPair(accountId: newSignerAccountId)
        let signer = Ed25519PasskeySigner(publicKey: Data(kp.publicKey.bytes),
                                          expiration: expiration,
                                          limits: limits,
                                          storage: storage)
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "add_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Creates a transaction that updates the ed25519 signer of the wallet,
    /// identified by [signerAccountId].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - signerAccountId: Stellar account id of the signer to be updated
    ///   - limits: Optional. Limits to be applied to the signer (e.g. policy)
    ///   - storage: Optional. Storage type for the signer (e.g. temporary, persistent).
    ///   - expiration: Optional. Sequence number of the ledger at wich the signer should expire.
    ///
    public func updateEd25519(txSourceAccountId:String,
                              signerAccountId:String,
                              limits:[PasskeyAddressLimits]? = nil,
                              storage:PasskeySignerStorage? = nil,
                              expiration:UInt32? = nil) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        let kp = try KeyPair(accountId: signerAccountId)
        let signer = Ed25519PasskeySigner(publicKey: Data(kp.publicKey.bytes),
                                          expiration: expiration,
                                          limits: limits,
                                          storage: storage)
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "update_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Creates a transaction that removes the ed25519 signer of the wallet,
    /// identified by [signerAccountId].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - signerAccountId: Stellar account id of the signer to be removed
    ///
    public func removeEd25519(txSourceAccountId:String,
                              signerAccountId:String) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        let kp = try KeyPair(accountId: signerAccountId)
        let signer = Ed25519PasskeySigner(publicKey: Data(kp.publicKey.bytes))
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "remove_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Creates a transaction that adds a policy to the wallet,
    /// identified by the [policyContractId].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - policyContractId: Contract id of the soroban policy contract.
    ///   - limits: Optional. Limits to be applied
    ///   - storage: Optional. Storage type for the signer (e.g. temporary, persistent).
    ///   - expiration: Optional. Sequence number of the ledger at wich the policy should expire.
    ///
    public func addPolicy(txSourceAccountId:String,
                          policyContractId:String,
                          limits:[PasskeyAddressLimits]? = nil,
                          storage:PasskeySignerStorage? = nil,
                          expiration:UInt32? = nil) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let policyContractAddress = try SCAddressXDR(contractId: policyContractId)
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        let signer = PolicyPasskeySigner(policyAddress: policyContractAddress,
                                         expiration: expiration,
                                         limits: limits,
                                         storage: storage)
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "add_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Creates a transaction that updates a policy of the wallet,
    /// identified by the [policyContractId].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - policyContractId: Contract id of the soroban policy contract.
    ///   - limits: Optional. Limits to be applied
    ///   - storage: Optional. Storage type for the signer (e.g. temporary, persistent).
    ///   - expiration: Optional. Sequence number of the ledger at wich the policy should expire.
    ///
    public func updatePolicy(txSourceAccountId:String,
                             policyContractId:String,
                             limits:[PasskeyAddressLimits]? = nil,
                             storage:PasskeySignerStorage? = nil,
                             expiration:UInt32? = nil) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let policyContractAddress = try SCAddressXDR(contractId: policyContractId)
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        let signer = PolicyPasskeySigner(policyAddress: policyContractAddress,
                                         expiration: expiration,
                                         limits: limits,
                                         storage: storage)
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "update_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Creates a transaction that removes a policy of the wallet,
    /// identified by the [policyContractId].
    /// Before calling this function, you must first connect your passkey kit instance
    /// to the wallet by using the [connectWallet] function.
    /// Returns a transaction, that can be sent by you to your soroban rpc server
    /// after signing with the source account keypair.
    ///
    /// - Parameters:
    ///   - txSourceAccountId: Stellar account id of the source account to be used to create the transaction
    ///   - policyContractId: Contract id of the soroban policy contract.
    ///
    public func removePolicy(txSourceAccountId:String,
                             policyContractId:String) async throws -> Transaction {
        
        if (self.keyId == nil) {
            throw PasskeyKitError.runtimeError("Wallet must be connected. Call connectWallet first.")
        }
        
        let policyContractAddress = try SCAddressXDR(contractId: policyContractId)
        
        let contractId = try deriveContractId(keyId: self.keyId!)
        let signer = PolicyPasskeySigner(policyAddress: policyContractAddress)
        
        let op = try InvokeHostFunctionOperation.forInvokingContract(contractId: contractId,
                                                                     functionName: "remove_signer",
                                                                     functionArguments: [signer.toSCValXDR()])
        return try await txForInvokeHostFunctionOp(txSourceAccountId: txSourceAccountId, op: op)
    }
    
    /// Signs a SorobanAuthorizationEntryXDR with passkey credentials. Make sure that the
    /// [entry] has credentials.address with the expiration ledger sequence correctly set or provide the [signatureExpirationLedger] you would like to be set.
    /// Provide a [signWithPasskey] function,  so that the user can be asked for signing with their credentials. Returns a signed copy of the provided entry.
    ///
    /// - Parameters:
    ///   - entry: Entry to be signed
    ///   - signWithPasskey: Function used to ask the user to sign with their passkey credentials.
    ///   - signatureExpirationLedger: Optional. The signature exiration ledger to be set.
    ///
    public func signedAuthEntryWithPasskey(entry: SorobanAuthorizationEntryXDR, signWithPasskey:((_ challenge:Data, _ rpId:String) async throws -> PasskeyCredentialSigningResponse), signatureExpirationLedger:UInt32? = nil) async throws -> SorobanAuthorizationEntryXDR {
        
        var result = entry
        let payload = try getAuthPayload(entry: result, signatureExpirationLedger:signatureExpirationLedger)
        let signingResponse = try await signWithPasskey(payload, rpId)
        let compactSignature = try normalizedSignature(signature: signingResponse.signature)
        
        let scKey = Secp256r1PasskeySignerKey(keyId: signingResponse.credentialID)
        let scVal = Secp256r1Signature(authenticatorData: signingResponse.authenticatorData,
                                       clientDataJson: signingResponse.clientDataJSON,
                                       signature: compactSignature)
        let signature = SCMapEntryXDR(key: scKey.toSCValXDR(), val: scVal.toSCValXDR())
        try addSignatureToEntry(entry: &result,
                                signature: signature,
                                signatureExpirationLedger: signatureExpirationLedger)
        return result
        
    }
    
    /// Signs a SorobanAuthorizationEntryXDR with the [signerKeyPair] as an ed25519 signer. Make sure that the
    /// [entry] has credentials.address with the expiration ledger sequence correctly set or provide the [signatureExpirationLedger] you would like to be set.
    /// Provide [signerKeyPair] including the private key for signing.  Returns a signed copy of the provided entry.
    ///
    /// - Parameters:
    ///   - entry: Entry to be signed
    ///   - signerKeyPair: Keypair of the signer including the private key.
    ///   - signatureExpirationLedger: Optional. The signature exiration ledger to be set.
    ///
    public func signedAuthEntryWithKeyPair(entry: SorobanAuthorizationEntryXDR,
                                           signerKeyPair:KeyPair,
                                           signatureExpirationLedger:UInt32? = nil) throws -> SorobanAuthorizationEntryXDR {
        if signerKeyPair.privateKey == nil {
            throw PasskeyKitError.runtimeError("Invalid signer keypair. Must contain private key!")
        }
        
        var result = entry
        let payload = try getAuthPayload(entry: result, signatureExpirationLedger:signatureExpirationLedger)
        let payloadSignature = signerKeyPair.sign([UInt8](payload))
        let scKey = Ed25519PasskeySignerKey(publicKey: Data(signerKeyPair.publicKey.bytes))
        let scVal = Ed25519Signature(signature: Data(payloadSignature))
        let signature = SCMapEntryXDR(key: scKey.toSCValXDR(), val: scVal.toSCValXDR())
        try addSignatureToEntry(entry: &result,
                                signature: signature,
                                signatureExpirationLedger: signatureExpirationLedger)
        return result
    }
    
    /// Signs a SorobanAuthorizationEntryXDR with the [policyContractId] as a policy signer. Make sure that the
    /// [entry] has credentials.address with the expiration ledger sequence correctly set or provide the [signatureExpirationLedger] you would like to be set.
    ///
    /// - Parameters:
    ///   - entry: Entry to be signed
    ///   - policyContractId: Contract id of the policy
    ///   - signatureExpirationLedger: Optional. The signature exiration ledger to be set.
    ///
    public func signedAuthEntryWithPolicy(entry: SorobanAuthorizationEntryXDR, policyContractId:String, signatureExpirationLedger:UInt32? = nil) throws -> SorobanAuthorizationEntryXDR {
        
        var result = entry
        let scKey = PolicyPasskeySignerKey(policyAddress: try SCAddressXDR(contractId: policyContractId))
        let scVal = PolicySignature()
        let signature = SCMapEntryXDR(key: scKey.toSCValXDR(), val: scVal.toSCValXDR())
        try addSignatureToEntry(entry: &result,
                                signature: signature,
                                signatureExpirationLedger: signatureExpirationLedger)
        return result
        
    }
    
    /// Signs all soroban authorization entries of the transaction [tx] with passkey credentials. Make sure that all
    /// entries have credentials.address with the expiration ledger sequence correctly set or provide a [signaturesExpirationLedger]  you would like to be set.
    /// Provide  a [signWithPasskey] so that the user can be asked for their passkey credentials for signing.
    ///
    ///
    /// - Parameters:
    ///   - tx: Transaction containing the entries to be signed
    ///   - signWithPasskey: Function used to ask the user to sign with their passkey credentials.
    ///   - signatureExpirationLedger: Optional. The signature exiration ledger to be set.
    ///
    public func signTxAuthEntriesWithPasskey(tx:inout Transaction,
                                             signWithPasskey:((_ challenge:Data, _ rpId:String) async throws -> PasskeyCredentialSigningResponse),
                                             signatureExpirationLayer:UInt32? = nil) async throws -> Void {
        
        var signedAuthEntries:[SorobanAuthorizationEntryXDR] = []
        for operation in tx.operations {
            if let op = operation as? InvokeHostFunctionOperation {
                for authEntry in op.auth {
                    signedAuthEntries.append(try await signedAuthEntryWithPasskey(entry: authEntry,
                                                                                  signWithPasskey: signWithPasskey,
                                                                                  signatureExpirationLedger: signatureExpirationLayer))
                }
            }
        }
        tx.setSorobanAuth(auth: signedAuthEntries)
    }
    
    /// Signs all soroban authorization entries of the transaction[tx] with the given [signerKeypair] as a ed25519 signer.
    /// Make sure that all entries have credentials.address with the expiration ledger sequence correctly set or provide a [signaturesExpirationLedger]
    /// to be set before signing. Provide [signerKeypair] including the private key for signing.
    ///
    /// - Parameters:
    ///   - tx: Transaction containing the entries to be signed
    ///   - signerKeyPair: Keypair of the signer, including the private key.
    ///   - signatureExpirationLedger: Optional. The signature exiration ledger to be set.
    ///
    public func signTxAuthEntriesWithKeyPair(tx:inout Transaction,
                                             signerKeyPair: KeyPair,
                                             signatureExpirationLayer:UInt32? = nil) throws -> Void {
        
        var signedAuthEntries:[SorobanAuthorizationEntryXDR] = []
        for operation in tx.operations {
            if let op = operation as? InvokeHostFunctionOperation {
                for authEntry in op.auth {
                    signedAuthEntries.append(try signedAuthEntryWithKeyPair(entry: authEntry,
                                                                            signerKeyPair: signerKeyPair,
                                                                            signatureExpirationLedger: signatureExpirationLayer))
                }
            }
        }
        
        tx.setSorobanAuth(auth: signedAuthEntries)
    }
    
    /// Signs all soroban authorization entries of the transaction[tx] with the given [policyContractId] as as a policy signer.  Make sure that all
    /// entries have credentials.address with the expiration ledger sequence correctly set or provide a [signaturesExpirationLedger]
    /// to be set before signing.
    ///
    /// - Parameters:
    ///   - tx: Transaction containing the entries to be signed
    ///   - policyContractId: Contract id of the policy to be used for signing.
    ///   - signatureExpirationLedger: Optional. The signature exiration ledger to be set.
    ///
    public func signTxAuthEntriesWithPolicy(tx:inout Transaction,
                                            policyContractId: String,
                                            signatureExpirationLayer:UInt32? = nil)  throws -> Void {
        
        var signedAuthEntries:[SorobanAuthorizationEntryXDR] = []
        for operation in tx.operations {
            if let op = operation as? InvokeHostFunctionOperation {
                for authEntry in op.auth {
                    signedAuthEntries.append(try signedAuthEntryWithPolicy(entry: authEntry,
                                                                           policyContractId: policyContractId,
                                                                           signatureExpirationLedger: signatureExpirationLayer))
                }
            }
        }
        tx.setSorobanAuth(auth: signedAuthEntries)
    }
    
    private func getPublicKey(rawAttestationObject:Data) async throws -> Data {
        // see: https://www.w3.org/TR/webauthn-2/#attestation-object
        let publicKeykPrefixSlice = Data([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
        let range = rawAttestationObject.range(of: publicKeykPrefixSlice)
        guard let range =  range else {
            throw PasskeyKitError.runtimeError("Could not find public key in rawAttestationObject")
        }
        
        let x = rawAttestationObject.subdata(in: range.upperBound ..< range.upperBound + 32)
        let y = rawAttestationObject.subdata(in: 35 + range.upperBound ..< range.upperBound + 67)
        
        var pk = Data([0x04]) // (0x04 prefix) https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
        pk.append(x)
        pk.append(y)
        return pk
    }
    
    private func normalizedSignature(signature:Data) throws -> Data {
        // Decode the DER signature
        var offset = 2
        let rLength = Int(signature[offset + 1])
        let r = signature.subdata(in: (offset + 2)..<(offset + 2 + rLength))
        
        offset = offset + 2 + rLength
        let sLength = Int(signature[offset + 1])
        let s = signature.subdata(in: (offset + 2)..<(offset + 2 + sLength))
        
        // Convert r and s to BigInt
        let rBigInt = BInt(number: r.base16EncodedString(), withBase: 16)!
        var sBigInt = BInt(number: s.base16EncodedString(), withBase: 16)!
        
        // Ensure s is in the low-S form
        // https://github.com/stellar/stellar-protocol/discussions/1435#discussioncomment-8809175
        // https://discord.com/channels/897514728459468821/1233048618571927693
        // Define the order of the curve secp256r1
        // https://github.com/RustCrypto/elliptic-curves/blob/master/p256/src/lib.rs#L72

        let curveOrder = BInt(number: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", withBase: 16)!
        let halfCurveOrder = curveOrder / 2
        if sBigInt > halfCurveOrder {
            sBigInt = curveOrder - sBigInt
        }
        
        // Convert back to buffers and ensure they are 32 bytes
        let rPadded = rBigInt.asString(withBase: 16).leftPadded(toLength: 64, withPad: "0")
        let sLowS = sBigInt.asString(withBase: 16).leftPadded(toLength: 64, withPad: "0")
        
        let rPaddedBytes = try Data(base16Encoded: rPadded)
        let sLowBytes = try Data(base16Encoded: sLowS)
        
        // Concatenate r and low-s
        var result = Data()
        result.append(rPaddedBytes)
        result.append(sLowBytes)
        return result
    
    }
    
    private func getAuthPayload(entry:SorobanAuthorizationEntryXDR, signatureExpirationLedger:UInt32? = nil) throws -> Data {
        guard let addressCredentials = entry.credentials.address else {
            throw PasskeyKitError.runtimeError("Entry has no address credentials")
        }
        
        let preimageSa = HashIDPreimageSorobanAuthorizationXDR(networkID: WrappedData32(network.networkId),
                                                               nonce: addressCredentials.nonce,
                                                               signatureExpirationLedger: signatureExpirationLedger ?? addressCredentials.signatureExpirationLedger,
                                                               invocation: entry.rootInvocation)
        
        let preimage = HashIDPreimageXDR.sorobanAuthorization(preimageSa)
        var encodedPreimage = try XDREncoder.encode(preimage)
        let encodedPreimageData = Data(bytes: &encodedPreimage, count: encodedPreimage.count)
        let encodedPreimageDataHashed = Data(Digest.sha256([UInt8](encodedPreimageData)))
        return encodedPreimageDataHashed
    }
    
    private func txForInvokeHostFunctionOp(txSourceAccountId:String, op:InvokeHostFunctionOperation) async throws -> Transaction {
        let accountResponeEnum = await server.getAccount(accountId: txSourceAccountId)
        switch accountResponeEnum {
        case .success(let account):
            let transaction = try Transaction(sourceAccount: account, operations: [op], memo: Memo.none)
            let simulateTxRequest = SimulateTransactionRequest(transaction: transaction)
            let simulateTxResponseEnum = await server.simulateTransaction(simulateTxRequest: simulateTxRequest)
            switch simulateTxResponseEnum {
            case .success(let simulateResponse):
                if let error = simulateResponse.error {
                    throw PasskeyKitError.runtimeError("\(error)")
                }
                transaction.setSorobanTransactionData(data: simulateResponse.transactionData!)
                transaction.addResourceFee(resourceFee: simulateResponse.minResourceFee!)
                transaction.setSorobanAuth(auth: simulateResponse.sorobanAuth)
                return transaction
            case .failure(_):
                throw PasskeyKitError.runtimeError("Could not simulate transaction")
            }
        case .failure(_):
            throw PasskeyKitError.runtimeError("Could not find source account: \(txSourceAccountId)")
        }
    }
    
    private func addSignatureToEntry(entry: inout SorobanAuthorizationEntryXDR, signature:SCMapEntryXDR, signatureExpirationLedger:UInt32? = nil) throws -> Void {
        guard var addressCredentials = entry.credentials.address else {
            throw PasskeyKitError.runtimeError("Entry has no address credentials")
        }
        
        let currentSig = addressCredentials.signature
        switch currentSig {
        case .void:
            addressCredentials.signature = SCValXDR.vec([SCValXDR.map([signature])])
            addressCredentials.signatureExpirationLedger = signatureExpirationLedger ?? addressCredentials.signatureExpirationLedger
            entry.credentials = SorobanCredentialsXDR.address(addressCredentials)
            return
        case .vec(let array):
            if let signatures = array, let firstElement = signatures.first {
                switch firstElement {
                case .map(let array):
                    if var sigMapEntries = array {
                        sigMapEntries.append(signature)
                        let sorted = sigMapEntries.sorted { (first, second) -> Bool in
                            guard let firstElemA = first.key.vec?.first, let firstElemB = second.key.vec?.first else {
                                return false
                            }
                            guard let keyA = firstElemA.symbol, let keyB = firstElemB.symbol else {
                                return false
                            }
                            guard let valA64 = firstElemA.xdrEncoded, let valB64 = firstElemB.xdrEncoded else {
                                return false
                            }
                            
                            return (keyA + valA64) < (keyB + valB64)
                        }
                        addressCredentials.signature = SCValXDR.vec([SCValXDR.map(sorted)])
                        addressCredentials.signatureExpirationLedger = signatureExpirationLedger ?? addressCredentials.signatureExpirationLedger
                        entry.credentials = SorobanCredentialsXDR.address(addressCredentials)
                        return
                    }
                default:
                    throw PasskeyKitError.runtimeError("Current signature's first element must be a map")
                }
            }
            addressCredentials.signature = SCValXDR.vec([SCValXDR.map([signature])])
            addressCredentials.signatureExpirationLedger = signatureExpirationLedger ?? addressCredentials.signatureExpirationLedger
            entry.credentials = SorobanCredentialsXDR.address(addressCredentials)
        default:
            throw PasskeyKitError.runtimeError("Entry has invalid address credentials signature")
        }
    }
    
    private func createAndSignDeployTx(keyId:Data, publicKey:Data) async throws -> Transaction {
        let sourceAccId = walletKeyPair.accountId
        let getAccountResponse = await server.getAccount(accountId: sourceAccId)
        var sourceAccount:Account? = nil
        switch getAccountResponse {
        case .success(let response):
            sourceAccount = response
        case .failure(let error):
            throw error
        }
        
        let signer = Secp256r1PasskeySigner(keyId: keyId,
                                            publicKey: publicKey,
                                            storage: PasskeySignerStorage.persistent)
        
        let operation = try InvokeHostFunctionOperation.forCreatingContractWithConstructor(wasmId: wasmHash, address: SCAddressXDR(accountId: sourceAccount!.accountId), constructorArguments: [signer.toSCValXDR()], salt: WrappedData32(getContractSalt(keyId: keyId)))
        
        let transaction = try! Transaction(sourceAccount: sourceAccount!,
                                           operations: [operation],
                                           memo: Memo.none)
        
        let simulateTxRequest = SimulateTransactionRequest(transaction: transaction)
        var simulateTxResponse:SimulateTransactionResponse? = nil
        let simulateTxResponseEnum = await server.simulateTransaction(simulateTxRequest: simulateTxRequest)
        switch simulateTxResponseEnum {
        case .success(let simulateResponse):
            if let error = simulateResponse.error {
                throw PasskeyKitError.runtimeError("\(error)")
            }
            simulateTxResponse = simulateResponse
        case .failure(let error):
            throw error
        }
        
        transaction.setSorobanTransactionData(data: simulateTxResponse!.transactionData!)
        transaction.addResourceFee(resourceFee: simulateTxResponse!.minResourceFee!)
        transaction.setSorobanAuth(auth: simulateTxResponse!.sorobanAuth)
        
        try transaction.sign(keyPair: walletKeyPair, network: network)
        
        return transaction
        
    }
    
    private func getContractSalt(keyId:Data) -> Data {
        return Data(Digest.sha256([UInt8](keyId)))
    }
    
    private func deriveContractId(keyId:Data) throws -> String {
        let contractSalt = getContractSalt(keyId: keyId)
        
        let contractIDPreimage = ContractIDPreimageXDR.fromAddress(ContractIDPreimageFromAddressXDR.init(address: try SCAddressXDR.init(accountId: walletKeyPair.accountId),
                                                                                                         salt: WrappedData32(contractSalt)))
        let hashIDPreimageContractID = HashIDPreimageContractIDXDR(networkID: WrappedData32(network.networkId),
                                                                   contractIDPreimage: contractIDPreimage)
        let preimage = HashIDPreimageXDR.contractID(hashIDPreimageContractID)
        var encodedPreimage = try XDREncoder.encode(preimage)
        let encodedPreimageData = Data(bytes: &encodedPreimage, count: encodedPreimage.count)
        let encodedPreimageDataHashed = Data(Digest.sha256([UInt8](encodedPreimageData)))
        return try encodedPreimageDataHashed.encodeContractId()
    }
    
}

extension String {
    func leftPadded(toLength: Int, withPad character: Character) -> String {
        let stringLength = self.count
        if stringLength < toLength {
            return String(repeatElement(character, count: toLength - stringLength)) + self
        } else {
            return String(self.suffix(toLength))
        }
    }
}

extension DateFormatter {
    static let posixFormatter : DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()
}
