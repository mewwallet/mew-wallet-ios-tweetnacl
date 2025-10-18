//
//  TweetNacl.swift
//  MEWwalletTweetNacl
//
//  Created by Mikhail Nikanorov on 6/15/21.
//  Copyright © 2021 MyEtherWallet Inc. All rights reserved.
//

import Foundation
import tweetnacl_lib

struct Constants {
  static let PublicKeyLength = 32
  static let SecretKeyLength = 32
  static let BeforeNMLength = 32
  
  enum SecretBox {
    static let keyLength = 32
    static let nonceLength = 24
    static let zeroLength = 32
    static let boxZeroLength = 16
  }
  
  enum Sign {
    static let signatureLength = 64
    static let publicKeyLength = 32
    static let secretKeyLength = 64
    static let seedLength = 32
  }
}

public enum TweetNaclError: LocalizedError {
  case invalidSecretKey
  case invalidPublicKey
  case invalidKey
  case invalidNonce
  case invalidSeed
  case tweetNacl(String)
  
  public var errorDescription: String? {
    switch self {
    case .invalidSecretKey: return "Wrong SecretKey length"
    case .invalidPublicKey: return "Wrong PublicKey length"
    case .invalidKey:       return "Wrong Key length"
    case .invalidNonce:     return "Wrong Nonce length"
    case .invalidSeed:      return "Wrong Seed length"
    case .tweetNacl:        return "Internal TweetNacl error"
    }
  }
  
  public var failureReason: String? {
    switch self {
    case .invalidSecretKey:       return "SecretKey length should be \(Constants.SecretKeyLength) bytes length"
    case .invalidPublicKey:       return "PublicKey should be \(Constants.PublicKeyLength) bytes length"
    case .invalidKey:             return "Key should be \(Constants.SecretBox.keyLength) bytes length"
    case .invalidNonce:           return "Nonce should be \(Constants.SecretBox.nonceLength) bytes length"
    case .invalidSeed:            return "Seed should be \(Constants.Sign.seedLength) bytes length"
    case let .tweetNacl(message): return "TweetNacl error: \(message)"
    }
  }
  
  public var recoverySuggestion: String? {
    switch self {
    case .invalidSecretKey: return "Check SecretKey length"
    case .invalidPublicKey: return "Check PublicKey length"
    case .invalidKey:       return "Check Key length"
    case .invalidNonce:     return "Check Nonce length"
    case .invalidSeed:      return "Check Seed length"
    case .tweetNacl:        return "Internal TweetNacl error"
    }
  }
  
  public var localizedDescription: String {
    return "\(self.errorDescription ?? ""). Recovery: \(self.recoverySuggestion ?? "")"
  }
}

public class TweetNacl {
  
  // MARK: - Keys

  /// Creates key pair on curve25519 as specified in EIP1024. Pass nil to create a new key pair or an Ethereum private key
  /// to create a key pair linked to an Ethereum key pair.
  /// Based on nacl.box.keyPair.fromSecretKey and nacl.box.keyPair
  /// - Parameter fromSecretKey: Ethereum private key
  /// - Returns: curve25519 key pair
  public static func keyPair(fromSecretKey: Data? = nil) throws -> (publicKey: Data, secretKey: Data) {
    var sk: [UInt8]
    if let fromSecretKey = fromSecretKey {
      guard fromSecretKey.count == Constants.SecretKeyLength else { throw TweetNaclError.invalidSecretKey }
      sk = [UInt8](fromSecretKey)
    } else {
        sk = [UInt8](repeating: 0, count: Constants.SecretKeyLength)
        let status = SecRandomCopyBytes(kSecRandomDefault, Constants.SecretKeyLength, &sk)
        guard status == errSecSuccess else {
            throw TweetNaclError.tweetNacl("Secure random bytes error")
        }
    }
          
    var pk = [UInt8](repeating: 0, count: Constants.PublicKeyLength)
    let result = crypto_scalarmult_curve25519_tweet_base(&pk, &sk)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.keyPair] Internal error code: \(result)") }
    return (Data(pk), Data(sk))
  }
  
  /// Generates an Ed25519 key pair from a given seed.
  ///
  /// This method uses the TweetNaCl implementation (`crypto_sign_ed25519_tweet_keypair`) to create
  /// a public/secret key pair suitable for Ed25519 signing operations.
  /// The provided seed must be exactly `Constants.Sign.seedLength` bytes long.
  ///
  /// - Parameters:
  ///   - seed: The seed data from which the key pair will be derived.
  ///     Must be `Constants.Sign.seedLength` bytes.
  ///
  /// - Returns:
  ///   A tuple containing:
  ///   - `publicKey`: The Ed25519 public key (`Constants.Sign.publicKeyLength` bytes).
  ///   - `secretKey`: The Ed25519 secret key (`Constants.Sign.secretKeyLength` bytes).
  ///
  /// - Throws:
  ///   - `TweetNaclError.invalidSeed` if the seed length is invalid.
  ///   - `TweetNaclError.tweetNacl` if the underlying `crypto_sign_ed25519_tweet_keypair` function fails.
  ///
  /// - Note:
  ///   The generated keys are suitable for use with the `sign` and `verify` methods in this API.
  public static func signKeyPair(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
    guard seed.count == Constants.Sign.seedLength else {
      throw TweetNaclError.invalidSeed
    }
    var sk: [UInt8] = [UInt8](repeating: 0, count: Constants.Sign.secretKeyLength)
    var pk: [UInt8] = [UInt8](repeating: 0, count: Constants.Sign.publicKeyLength)
    
    sk.replaceSubrange(0..<Constants.Sign.publicKeyLength, with: seed[0..<Constants.Sign.publicKeyLength])
    
    let result = crypto_sign_ed25519_tweet_keypair(&pk, &sk)
    guard result == 0 else {
      throw TweetNaclError.tweetNacl("Internal error")
    }
    
    return (Data(pk), Data(sk))
  }
    
  /// Pre-calculate shared secret key
  /// Based on nacl.box.before
  /// - Parameters:
  ///   - publicKey: public key
  ///   - secretKey: private key
  /// - Returns: shared key
  internal static func before(publicKey: Data, secretKey: Data) throws -> Data {
    guard publicKey.count == Constants.PublicKeyLength else { throw TweetNaclError.invalidPublicKey }
    guard secretKey.count == Constants.SecretKeyLength else { throw TweetNaclError.invalidSecretKey }
      
    var publicKey = [UInt8](publicKey)
    var secretKey = [UInt8](secretKey)
    var k = [UInt8](repeating: 0, count: Constants.BeforeNMLength)
      
    let result = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(&k, &publicKey, &secretKey)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.before] Internal error code: \(result)") }
      
    return Data(k)
  }
  
  // MARK: - Sign
  
  /// Signs a message using the Ed25519 signature scheme.
  ///
  /// This method uses the TweetNaCl implementation (`crypto_sign_ed25519_tweet`) to generate a
  /// deterministic Ed25519 signature for the provided message using the given secret key.
  ///
  /// - Parameters:
  ///   - message: The message data to sign.
  ///   - secretKey: The Ed25519 secret key (must be `Constants.Sign.secretKeyLength` bytes long).
  ///   - onlySignature: If `true` (default), returns only the signature bytes. If `false`,
  ///     returns the concatenation of the signature and the original message.
  ///
  /// - Returns:
  ///   A `Data` object containing either:
  ///   - The Ed25519 signature (`Constants.Sign.signatureLength` bytes) if `onlySignature` is `true`.
  ///   - The signature followed by the message (`signatureLength + message.count` bytes) if `onlySignature` is `false`.
  ///
  /// - Throws:
  ///   - `TweetNaclError.invalidSecretKey` if the `secretKey` length is invalid.
  ///   - `TweetNaclError.tweetNacl` if the underlying `crypto_sign_ed25519_tweet` function fails.
  ///
  /// - Note:
  ///   This method produces deterministic signatures — the same message and secret key will
  ///   always yield the same signature.
  public static func sign(message: Data, secretKey: Data, onlySignature: Bool = true) throws -> Data {
    guard secretKey.count == Constants.Sign.secretKeyLength else { throw TweetNaclError.invalidSecretKey }
    
    var signedMessage = [UInt8](repeating: 0x00, count: Constants.Sign.signatureLength + message.count)
    var length: UInt64 = 0
    var secretKey = [UInt8](secretKey)
    var message = [UInt8](message)
    
    let result = crypto_sign_ed25519_tweet(&signedMessage, &length, &message, UInt64(message.count), &secretKey)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.sign] Internal error code: \(result)") }
    if onlySignature {
      return Data(signedMessage[0..<Constants.Sign.signatureLength])
    } else {
      return Data(signedMessage)
    }
  }
  
  /// Verifies a message using the Ed25519 signature scheme.
  /// 
  /// This method uses the TweetNaCl implementation (`crypto_sign_ed25519_tweet_open`)
  /// to verify a detached Ed25519 signature against the provided message and public key.
  /// 
  /// The verification succeeds if:
  /// - The signature length is exactly `Constants.Sign.signatureLength` bytes.
  /// - The public key length is exactly `Constants.Sign.publicKeyLength` bytes.
  /// - `crypto_sign_ed25519_tweet_open` successfully recovers the original message from the
  ///   concatenated signature and message bytes.
  /// - The recovered message exactly matches the provided message.
  /// 
  /// - Parameters:
  ///   - message: The message data to verify.
  ///   - signature: The Ed25519 signature to verify (`Constants.Sign.signatureLength` bytes).
  ///   - publicKey: The Ed25519 public key associated with the signature
  ///                (`Constants.Sign.publicKeyLength` bytes).
  /// 
  /// - Returns: `true` if the signature is valid for the given message and public key; otherwise, `false`.
  /// 
  /// - Note:
  ///   This function expects a *detached* Ed25519 signature (signature and message are provided separately),
  ///   but internally uses `crypto_sign_ed25519_tweet_open`, which operates on a
  ///   "signature || message" concatenation, to perform the verification.
  public static func verify(message: Data, signature: Data, publicKey: Data) -> Bool {
    guard signature.count == Constants.Sign.signatureLength,
          publicKey.count == Constants.Sign.publicKeyLength else { return false }
    
    var publicKey = [UInt8](publicKey)
    let message = [UInt8](message)
    let signature = [UInt8](signature)
    
    // signature || message
    var signedMessage = signature + message
    
    // recovered must be at least signedMessage.count bytes
    var recovered = [UInt8](repeating: 0, count: signedMessage.count)
    var length: UInt64 = 0
    
    let result = crypto_sign_ed25519_tweet_open(&recovered, &length, &signedMessage, UInt64(signedMessage.count), &publicKey)
    
    // Valid if open() returns 0 AND recovered message matches input
    guard result == 0, Int(length) == message.count else { return false }
    return recovered.prefix(Int(length)).elementsEqual(message)
  }
    
  // MARK: - Decryption
    
  /// Decrypts encrypted message
  /// Based on nacl.box.open
  /// - Parameters:
  ///   - message: secret box
  ///   - nonce: unique nonce
  ///   - publicKey: public curve25519 key provided by sender
  ///   - secretKey: receiver's private curve25519 key to decrypt message
  /// - Returns: clear text
  public static func open(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data {
    let k = try before(publicKey: publicKey, secretKey: secretKey)
    return try open(box: message, nonce: nonce, key: k)
  }
  
  /// Decrypts encrypted message
  /// Based on nacl.secretbox.open
  /// - Parameters:
  ///   - box: secret box
  ///   - nonce: unique nonce
  ///   - key: private key
  /// - Returns: clear text of message
  public static func open(box: Data, nonce: Data, key: Data) throws -> Data {
    guard key.count == Constants.SecretBox.keyLength else { throw TweetNaclError.invalidKey }
    guard nonce.count == Constants.SecretBox.nonceLength else { throw TweetNaclError.invalidNonce }
    
    var cData = Data(count: Constants.SecretBox.boxZeroLength + box.count)
    cData.replaceSubrange(Constants.SecretBox.boxZeroLength..<cData.count, with: box)
    
    var m = [UInt8](repeating: 0, count: cData.count)
    var c = [UInt8](cData)
    var nonce = [UInt8](nonce)
    var key = [UInt8](key)
    
    let result = crypto_secretbox_xsalsa20poly1305_tweet_open(&m, &c, UInt64(cData.count), &nonce, &key)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.open] Internal error code: \(result)") }
    
    return Data(m[Constants.SecretBox.zeroLength..<c.count])
  }
    
  // MARK: - Encryption
    
  /// Encrypts message, creates secretbox
  /// Based on nacl.box
  /// - Parameters:
  ///   - message: Clear text message
  ///   - theirPublicKey: Recipient's public key
  ///   - mySecretKey: Sender's private key
  ///   - nonce: nonce (pass nil for random nonce)
  /// - Returns: secret box
  public static func box(message: Data, recipientPublicKey: Data, senderSecretKey: Data, nonce: Data? = nil) throws -> (box: Data, nonce: Data) {
    let k = try before(publicKey: recipientPublicKey, secretKey: senderSecretKey)
    let nonce = try nonce ?? randomNonce()
    let box = try secretbox(message: message, nonce: nonce, key: k)
    return (box: box, nonce: nonce)
  }
    
  /// Encrypts message, creates secretbox
  /// Based on nacl.secretbox
  /// - Parameters:
  ///   - message: Clear text message
  ///   - nonce: Unique nonce
  ///   - key: Shared secret key
  /// - Returns: secret box
  private static func secretbox(message: Data, nonce: Data, key: Data) throws -> Data {
    guard key.count == Constants.SecretBox.keyLength else { throw TweetNaclError.invalidKey }
    guard nonce.count == Constants.SecretBox.nonceLength else { throw TweetNaclError.invalidNonce }
      
    var mData = Data(count: Constants.SecretBox.zeroLength + message.count)
    mData.replaceSubrange(Constants.SecretBox.zeroLength ..< mData.count, with: message)
    var m = [UInt8](mData)
    var c = [UInt8](repeating: 0, count: m.count)
    var nonce = [UInt8](nonce)
    var key = [UInt8](key)
      
    let result = crypto_secretbox_xsalsa20poly1305_tweet(&c, &m, UInt64(m.count), &nonce, &key)
    guard result == 0 else { throw TweetNaclError.tweetNacl("[TweetNacl.secretbox] Internal error code: \(result)") }
    
    return Data(c[Constants.SecretBox.boxZeroLength..<c.count])
  }
  
  /// Checks that Ed25519 public key encodes a valid point on Edwards25519.
  /// Returns `true` iff the 32-byte key decodes successfully.
  /// - Parameter publicKey: The Ed25519 public key
  /// - Returns: `true` if the key is on curve; otherwise, `false`.
  public static func isOnCurve(publicKey: Data) throws -> Bool {
    guard publicKey.count == Constants.Sign.publicKeyLength else { throw TweetNaclError.invalidPublicKey }
    return publicKey.withUnsafeBytes { rawPtr -> Bool in
      let p = rawPtr.bindMemory(to: UInt8.self).baseAddress!
      
      return ed25519_is_on_curve(p) == 1
    }
  }
    
  private static func randomNonce() throws -> Data {
    var nonce = [UInt8](repeating: 0, count: Constants.SecretBox.nonceLength)
    let status = SecRandomCopyBytes(kSecRandomDefault, Constants.SecretBox.nonceLength, &nonce)
    guard status == errSecSuccess else {
      throw TweetNaclError.tweetNacl("Secure random bytes error")
    }
    return Data(nonce)
  }
}
