//
//  PasskeyKitError.swift
//
//
//  Created by Christian Rogobete on 21.02.25.
//

import Foundation

enum PasskeyKitError: Error {
    case runtimeError(String)
}

extension PasskeyKitError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .runtimeError(let val):
            return NSLocalizedString(val, comment: "PasskeyKit error")
        }
    }
}

