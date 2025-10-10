import Foundation
import Testing
@testable import mew_wallet_ios_tweetnacl

@Suite("TweetNacl tests")
struct mew_wallet_ios_tweetnacl {
  let nonce = "1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej"
  let ephemPublicKey = "FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ="
  let cipherText = "f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy"
  let privateKey = Data([0x7e, 0x53, 0x74, 0xec, 0x2e, 0xf0, 0xd9, 0x17, 0x61, 0xa6, 0xe7, 0x2f, 0xdf, 0x8f, 0x6a, 0xc6, 0x65, 0x51, 0x9b, 0xfd, 0xf6, 0xda, 0x0a, 0x23, 0x29, 0xcf, 0x0d, 0x80, 0x45, 0x14, 0xb8, 0x16])
  
  @Test("Decode")
  func decode() throws {
    let sk = try TweetNacl.keyPair(fromSecretKey: privateKey).secretKey
    let nonceData = try #require(Data(base64Encoded: self.nonce))
    let cipherTextData = try #require(Data(base64Encoded: self.cipherText))
    let ephemPublicKeyData = try #require(Data(base64Encoded: self.ephemPublicKey))
    let decrypted = try TweetNacl.open(
      message: cipherTextData,
      nonce: nonceData,
      publicKey: ephemPublicKeyData,
      secretKey: sk)
    
    let message = try #require(String(data: decrypted, encoding: .utf8))
    #expect(message == "My name is Satoshi Buterin")
  }
    
  @Test("Encode")
  func encode() throws {
    let receiverKeys = try TweetNacl.keyPair(fromSecretKey: privateKey)
    let ephemKeys = try TweetNacl.keyPair()
    let message = "My name is Satoshi Buterin".data(using: .utf8)!
    let nonceData = Data(base64Encoded: self.nonce)!
    
    #expect(String(data: receiverKeys.publicKey.base64EncodedData(), encoding: .utf8) == "C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=")
    #expect(String(data: nonceData.base64EncodedData(), encoding: .utf8) == "1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej")
      
    // encrypt
    let secretbox = try TweetNacl.box(message: message, recipientPublicKey: receiverKeys.publicKey, senderSecretKey: ephemKeys.secretKey, nonce: nonceData)
    let secretboxString = String(data: secretbox.box.base64EncodedData(), encoding: .utf8)!
    let expectedCiphertext = "f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy"
    #expect(secretboxString.count == expectedCiphertext.count)
    
    // decrypt
    let decrypted = try TweetNacl.open(message: secretbox.box, nonce: nonceData, publicKey: ephemKeys.publicKey, secretKey: receiverKeys.secretKey)
    let decryptedMessage = try #require(String(data: decrypted, encoding: .utf8))
    #expect(decryptedMessage == String(data: message, encoding: .utf8))
  }
    
  @Test("Encode random")
  func encodeRandom() throws {
    let message = "My name is Satoshi Buterin".data(using: .utf8)!
    let receiverKeys = try TweetNacl.keyPair(fromSecretKey: privateKey)
    let senderKeys = try TweetNacl.keyPair()
    let encoded = try TweetNacl.box(message: message, recipientPublicKey: receiverKeys.publicKey, senderSecretKey: senderKeys.secretKey)
        
    // decrypt
    let decrypted = try TweetNacl.open(message: encoded.box, nonce: encoded.nonce, publicKey: senderKeys.publicKey, secretKey: receiverKeys.secretKey)
    let decryptedMessage = try #require(String(data: decrypted, encoding: .utf8))
    #expect(decryptedMessage == String(data: message, encoding: .utf8))
  }
    
  @Test("Decode by sender")
  func decodeBySender() throws {
    let message = "My name is Satoshi Buterin".data(using: .utf8)!
    let receiverKeys = try TweetNacl.keyPair(fromSecretKey: privateKey)
    let senderKeys = try TweetNacl.keyPair()
    let (box, nonce) = try TweetNacl.box(message: message, recipientPublicKey: receiverKeys.publicKey, senderSecretKey: senderKeys.secretKey)
        
    // decrypt by sender
    let decrypted = try TweetNacl.open(message: box, nonce: nonce, publicKey: receiverKeys.publicKey, secretKey: senderKeys.secretKey)
    let decryptedMessage = try #require(String(data: decrypted, encoding: .utf8))
    #expect(decryptedMessage == String(data: message, encoding: .utf8))
  }
  
  @Test("Is on curve")
  func isOnCurve() async throws {
    let rfc8032key = Data([
      0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
      0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    ])
    try #expect(TweetNacl.isOnCurve(publicKey: rfc8032key) == true)
    
    
    // Identity element: y = 1, sign(x) = 0 → should decode successfully
    let identity = Data([0x01] + Array(repeating: 0x00, count: 31))
    try #expect(TweetNacl.isOnCurve(publicKey: identity) == true)
    
    // Valid deterministic keypairs derived from fixed seeds
    do {
      let seed0 = Data(repeating: 0x00, count: 32)
      let (pk0, _) = try TweetNacl.signKeyPair(seed: seed0)
      try #expect(TweetNacl.isOnCurve(publicKey: pk0) == true)
      
      let seedInc = Data((0..<32).map { UInt8($0) })
      let (pk1, _) = try TweetNacl.signKeyPair(seed: seedInc)
      try #expect(TweetNacl.isOnCurve(publicKey: pk1) == true)
    }
    
    // Invalid lengths — must throw an error
    do {
      let short = Data(repeating: 0x00, count: 31)
      let long  = Data(repeating: 0x00, count: 33)
      #expect(throws: TweetNaclError.self, performing: {
        try TweetNacl.isOnCurve(publicKey: short)
      })
      #expect(throws: TweetNaclError.self, performing: {
        try #expect(TweetNacl.isOnCurve(publicKey: long)  == false)
      })
    }
    
    // Random bytes — often still decode to a valid point.
    let invalidKey = Data([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0xCC, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x80, 0x00
    ])
    try #expect(TweetNacl.isOnCurve(publicKey: invalidKey) == false)
    
    // Same key as RFC 8032 but with flipped sign bit → still valid (x negated)
    var flipped = rfc8032key
    flipped[31] ^= 0x80
    try #expect(TweetNacl.isOnCurve(publicKey: flipped) == true)
  }
}
