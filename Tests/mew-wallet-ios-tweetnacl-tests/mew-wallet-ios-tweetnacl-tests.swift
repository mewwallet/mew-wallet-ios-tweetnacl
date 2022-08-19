import XCTest
@testable import mew_wallet_ios_tweetnacl

final class mew_wallet_ios_tweetnacl_tests: XCTestCase {
  let nonce = "1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej"
  let ephemPublicKey = "FBH1/pAEHOOW14Lu3FWkgV3qOEcuL78Zy+qW1RwzMXQ="
  let cipherText = "f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy"
  let privateKey = Data([0x7e, 0x53, 0x74, 0xec, 0x2e, 0xf0, 0xd9, 0x17, 0x61, 0xa6, 0xe7, 0x2f, 0xdf, 0x8f, 0x6a, 0xc6, 0x65, 0x51, 0x9b, 0xfd, 0xf6, 0xda, 0x0a, 0x23, 0x29, 0xcf, 0x0d, 0x80, 0x45, 0x14, 0xb8, 0x16])
  
  func testDecode() {
    do {
      let sk = try TweetNacl.keyPair(fromSecretKey: privateKey).secretKey
      guard let nonceData = Data(base64Encoded: self.nonce),
            let cipherTextData = Data(base64Encoded: self.cipherText),
            let ephemPublicKeyData = Data(base64Encoded: self.ephemPublicKey) else {
        XCTFail("Can't get data")
        return
      }
      let decrypted = try TweetNacl.open(
        message: cipherTextData,
        nonce: nonceData,
        publicKey: ephemPublicKeyData,
        secretKey: sk)
      
      guard let message = String(data: decrypted, encoding: .utf8) else {
        XCTFail("Can't create a string")
        return
      }
      XCTAssertEqual(message, "My name is Satoshi Buterin")
      debugPrint(message)
    } catch {
      XCTFail((error as? LocalizedError)?.failureReason ?? error.localizedDescription)
    }
  }
    
  func testEncode() throws {
    let receiverKeys = try TweetNacl.keyPair(fromSecretKey: privateKey)
    let ephemKeys = try TweetNacl.keyPair()
    let message = "My name is Satoshi Buterin".data(using: .utf8)!
    let nonceData = Data(base64Encoded: self.nonce)!
    
    XCTAssertEqual(String(data: receiverKeys.publicKey.base64EncodedData(), encoding: .utf8), "C5YMNdqE4kLgxQhJO1MfuQcHP5hjVSXzamzd/TxlR0U=")
    XCTAssertEqual(String(data: nonceData.base64EncodedData(), encoding: .utf8), "1dvWO7uOnBnO7iNDJ9kO9pTasLuKNlej")
      
    // encrypt
    let secretbox = try TweetNacl.box(message: message, recipientPublicKey: receiverKeys.publicKey, senderSecretKey: ephemKeys.secretKey, nonce: nonceData)
    let secretboxString = String(data: secretbox.box.base64EncodedData(), encoding: .utf8)!
    let expectedCiphertext = "f8kBcl/NCyf3sybfbwAKk/np2Bzt9lRVkZejr6uh5FgnNlH/ic62DZzy"
    XCTAssertEqual(secretboxString.count, expectedCiphertext.count)
    
    // decrypt
    let decrypted = try TweetNacl.open(message: secretbox.box, nonce: nonceData, publicKey: ephemKeys.publicKey, secretKey: receiverKeys.secretKey)
    guard let decryptedMessage = String(data: decrypted, encoding: .utf8) else {
      XCTFail("Can't create a string")
      return
    }
    XCTAssertEqual(decryptedMessage, String(data: message, encoding: .utf8))
  }
    
  func testEncodeRandom() throws {
    let message = "My name is Satoshi Buterin".data(using: .utf8)!
    let receiverKeys = try TweetNacl.keyPair(fromSecretKey: privateKey)
    let senderKeys = try TweetNacl.keyPair()
    let encoded = try TweetNacl.box(message: message, recipientPublicKey: receiverKeys.publicKey, senderSecretKey: senderKeys.secretKey)
        
    // decrypt
    let decrypted = try TweetNacl.open(message: encoded.box, nonce: encoded.nonce, publicKey: senderKeys.publicKey, secretKey: receiverKeys.secretKey)
    guard let decryptedMessage = String(data: decrypted, encoding: .utf8) else {
      XCTFail("Can't create a string")
      return
    }
    XCTAssertEqual(decryptedMessage, String(data: message, encoding: .utf8))
  }
    
  func testDecodeBySender() throws {
    let message = "My name is Satoshi Buterin".data(using: .utf8)!
    let receiverKeys = try TweetNacl.keyPair(fromSecretKey: privateKey)
    let senderKeys = try TweetNacl.keyPair()
    let (box, nonce) = try TweetNacl.box(message: message, recipientPublicKey: receiverKeys.publicKey, senderSecretKey: senderKeys.secretKey)
        
    // decrypt by sender
    let decrypted = try TweetNacl.open(message: box, nonce: nonce, publicKey: receiverKeys.publicKey, secretKey: senderKeys.secretKey)
    guard let decryptedMessage = String(data: decrypted, encoding: .utf8) else {
      XCTFail("Can't create a string")
      return
    }
    XCTAssertEqual(decryptedMessage, String(data: message, encoding: .utf8))
  }
}
