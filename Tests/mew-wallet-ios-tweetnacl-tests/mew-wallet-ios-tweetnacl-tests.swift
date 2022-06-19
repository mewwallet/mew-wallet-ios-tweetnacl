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
}
