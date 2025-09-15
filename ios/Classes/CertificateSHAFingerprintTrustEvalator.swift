import Foundation
import CryptoKit
import CommonCrypto
import Alamofire


final class CertificateSHAFingerprintTrustEvaluator: ServerTrustEvaluating {
    let pinnedFingerprints: [String]
    let type: String
    
    init(pinnedFingerprints: [String],  type: String) {
        self.type = type
        self.pinnedFingerprints = pinnedFingerprints.map { $0.lowercased() }
    }
    
    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        let policies: [SecPolicy] = [SecPolicyCreateSSL(true, host as CFString)]
        SecTrustSetPolicies(trust, policies as CFTypeRef)
        
        var result: SecTrustResultType = .invalid
        SecTrustEvaluate(trust, &result)
        
        let isServerTrusted = (result == .unspecified || result == .proceed)
        guard isServerTrusted else {
            throw AFError.serverTrustEvaluationFailed(
                reason: .trustEvaluationFailed(error: nil)
            )
        }
        
        let certificateCount = SecTrustGetCertificateCount(trust)
        guard certificateCount > 0 else {
            throw AFError.serverTrustEvaluationFailed(
                reason: .noCertificatesFound
            )
        }
        
        var isSecure = false
        let fps = self.pinnedFingerprints.compactMap { (val) -> String? in
            val.replacingOccurrences(of: " ", with: "")
        }
        
        // Check all certificates in the chain
        for index in 0..<certificateCount {
            guard let certificate = SecTrustGetCertificateAtIndex(trust, index) else {
                continue
            }
            
            let serverCertData = SecCertificateCopyData(certificate) as Data
            var serverCertSha = serverCertData.sha256().toHexString()
            
            if(type == "SHA1"){
                serverCertSha = serverCertData.sha1().toHexString()
            }
            
            isSecure = fps.contains(where: { (value) -> Bool in
                value.caseInsensitiveCompare(serverCertSha) == .orderedSame
            })
            
            // If we found a match, break out of the loop
            if isSecure {
                break
            }
        }
        
        if !isSecure {
            throw AFError.serverTrustEvaluationFailed(
                reason: .noCertificatesFound
            )
        }
        
    }
}

extension Data {
    func sha256() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        _ = self.withUnsafeBytes { buffer in
            CC_SHA256(buffer.baseAddress, CC_LONG(self.count), &digest)
        }
        
        return Data(bytes: digest, count: digest.count)
    }
    
    func sha1() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        
        _ = self.withUnsafeBytes { buffer in
            CC_SHA1(buffer.baseAddress, CC_LONG(self.count), &digest)
        }
        
        return Data(bytes: digest, count: digest.count)
    }
    
    func toHexString() -> String {
        return self.map { String(format: "%02hhx", $0) }.joined()
    }
}
