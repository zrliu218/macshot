import Foundation
import CryptoKit

/// Aliyun Machine Translation (通用版) adapter.
///
/// Uses the RPC-style `TranslateGeneral` API with HMAC-SHA1 request signing.
/// The free tier includes 1,000,000 characters per month; requests are sent
/// with a small concurrency limit to stay well inside the service QPS cap.
enum AliyunTranslationClient {

    struct Config {
        let accessKeyId: String
        let accessKeySecret: String
    }

    enum ClientError: LocalizedError {
        case missingCredentials
        case badResponse
        case api(code: String, message: String)

        var errorDescription: String? {
            switch self {
            case .missingCredentials:
                return "Aliyun AccessKey ID or Secret is missing. Add them in Settings."
            case .badResponse:
                return "Could not read the Aliyun translation response."
            case .api(let code, let message):
                return "Aliyun translation failed (\(code)): \(message)"
            }
        }
    }

    private static let endpoint = "https://mt.aliyuncs.com/"
    private static let maxChunkLength = 4500
    private static let maxConcurrentRequests = 4

    /// Translates each entry, preserving order and empty strings.
    static func translate(
        texts: [String],
        targetLang: String,
        config: Config,
        completion: @escaping (Result<[String], Error>) -> Void
    ) {
        let akid = config.accessKeyId.trimmingCharacters(in: .whitespacesAndNewlines)
        let secret = config.accessKeySecret.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !akid.isEmpty, !secret.isEmpty else {
            completion(.failure(ClientError.missingCredentials))
            return
        }

        let target = aliyunLanguageCode(targetLang)
        var results = Array(repeating: "", count: texts.count)
        let group = DispatchGroup()
        let semaphore = DispatchSemaphore(value: maxConcurrentRequests)
        let lock = NSLock()
        var firstError: Error?

        for (index, text) in texts.enumerated() {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                results[index] = text
                continue
            }

            group.enter()
            semaphore.wait()
            DispatchQueue.global(qos: .userInitiated).async {
                defer {
                    semaphore.signal()
                    group.leave()
                }

                let outcome = translateChunked(
                    text: trimmed,
                    target: target,
                    config: Config(accessKeyId: akid, accessKeySecret: secret)
                )
                lock.lock()
                switch outcome {
                case .success(let translated):
                    results[index] = translated
                case .failure(let error):
                    if firstError == nil { firstError = error }
                }
                lock.unlock()
            }
        }

        group.notify(queue: .main) {
            if let error = firstError {
                completion(.failure(error))
            } else {
                completion(.success(results))
            }
        }
    }

    // MARK: - Request

    private static func translateChunked(
        text: String,
        target: String,
        config: Config
    ) -> Result<String, Error> {
        let chunks = split(text, limit: maxChunkLength)
        var translatedParts: [String] = []

        for chunk in chunks {
            switch translateOne(text: chunk, target: target, config: config) {
            case .success(let value):
                translatedParts.append(value)
            case .failure(let error):
                return .failure(error)
            }
        }
        return .success(translatedParts.joined(separator: "\n"))
    }

    private static func translateOne(
        text: String,
        target: String,
        config: Config
    ) -> Result<String, Error> {
        var params: [String: String] = [
            "AccessKeyId": config.accessKeyId,
            "Action": "TranslateGeneral",
            "Format": "JSON",
            "FormatType": "text",
            "RegionId": "cn-hangzhou",
            "Scene": "general",
            "SignatureMethod": "HMAC-SHA1",
            "SignatureNonce": UUID().uuidString,
            "SignatureVersion": "1.0",
            "SourceLanguage": "auto",
            "SourceText": text,
            "TargetLanguage": target,
            "Timestamp": utcTimestamp(),
            "Version": "2018-10-12",
        ]

        let canonical = canonicalizedQuery(params)
        let stringToSign = "POST&%2F&" + percentEncode(canonical)
        let signature = sign(stringToSign, secret: config.accessKeySecret)
        params["Signature"] = signature

        var bodyComponents: [URLQueryItem] = []
        for key in params.keys.sorted() {
            bodyComponents.append(URLQueryItem(name: key, value: params[key]))
        }
        var body = URLComponents()
        body.queryItems = bodyComponents
        let bodyString = body.percentEncodedQuery ?? ""

        var request = URLRequest(url: URL(string: endpoint)!)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("macshot/4.3.0", forHTTPHeaderField: "User-Agent")
        request.httpBody = bodyString.data(using: .utf8)

        let sem = DispatchSemaphore(value: 0)
        var outcome: Result<String, Error> = .failure(ClientError.badResponse)

        URLSession.shared.dataTask(with: request) { data, response, error in
            defer { sem.signal() }
            if let error = error {
                outcome = .failure(error)
                return
            }
            guard let data = data else {
                outcome = .failure(ClientError.badResponse)
                return
            }
            do {
                guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    outcome = .failure(ClientError.badResponse)
                    return
                }
                let code = (json["Code"] as? String) ?? String(describing: json["Code"] ?? "")
                guard code == "200" else {
                    let message = (json["Message"] as? String) ?? "Unknown error"
                    outcome = .failure(ClientError.api(code: code, message: message))
                    return
                }
                guard let payload = json["Data"] as? [String: Any],
                      let translated = payload["Translated"] as? String else {
                    outcome = .failure(ClientError.badResponse)
                    return
                }
                outcome = .success(translated)
            } catch {
                outcome = .failure(error)
            }
        }.resume()

        sem.wait()
        return outcome
    }

    // MARK: - Signing helpers

    private static func canonicalizedQuery(_ params: [String: String]) -> String {
        params.keys.sorted().map { key in
            "\(percentEncode(key))=\(percentEncode(params[key] ?? ""))"
        }.joined(separator: "&")
    }

    private static func percentEncode(_ value: String) -> String {
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    private static func sign(_ stringToSign: String, secret: String) -> String {
        let key = SymmetricKey(data: Data((secret + "&").utf8))
        let signature = HMAC<Insecure.SHA1>.authenticationCode(
            for: Data(stringToSign.utf8),
            using: key
        )
        return Data(signature).base64EncodedString()
    }

    private static func utcTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return formatter.string(from: Date())
    }

    // MARK: - Language and chunking

    private static func aliyunLanguageCode(_ code: String) -> String {
        let lower = code.lowercased()
        // Aliyun uses "zh" / "zh-tw", not BCP-47 script tags like "zh-Hans".
        if lower.hasPrefix("zh-hant") || lower == "zh-tw" || lower == "zh-hk" || lower == "zh-mo" {
            return "zh-tw"
        }
        if lower.hasPrefix("zh") { return "zh" }
        if lower.hasPrefix("pt") { return "pt" }
        if lower.hasPrefix("nb") || lower.hasPrefix("no") { return "no" }
        if lower.hasPrefix("fil") || lower.hasPrefix("tl") { return "tl" }
        // Aliyun expects base language codes for the rest (en-US -> en, fr-CA -> fr).
        return lower.split(separator: "-").first.map(String.init) ?? lower
    }

    private static func split(_ text: String, limit: Int) -> [String] {
        guard text.count > limit else { return [text] }

        var chunks: [String] = []
        var current = ""

        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let candidate = current.isEmpty ? String(line) : current + "\n" + line
            if candidate.count <= limit {
                current = candidate
                continue
            }
            if !current.isEmpty {
                chunks.append(current)
                current = ""
            }
            if line.count <= limit {
                current = String(line)
            } else {
                var remainder = String(line)
                while remainder.count > limit {
                    let cut = remainder.index(remainder.startIndex, offsetBy: limit)
                    chunks.append(String(remainder[..<cut]))
                    remainder = String(remainder[cut...])
                }
                current = remainder
            }
        }
        if !current.isEmpty { chunks.append(current) }
        return chunks.isEmpty ? [text] : chunks
    }
}
