import Foundation
import Security

// MARK: - Secure Storage Function Namespace

/// Secure storage bridge functions.
/// Namespace: "WuninsuSecureStorage.*"
///
/// Values are Keychain items (generic passwords) that are readable only while the phone is unlocked and never
/// leave this device: no iCloud Keychain, no backups.
enum WuninsuSecureStorageFunctions {

    // MARK: - WuninsuSecureStorage.Get

    /// Parameters: key (string)
    /// Returns: {status: "found", value} or {status: "not_found"}
    class Get: BridgeFunction {
        func execute(parameters: [String: Any]) throws -> [String: Any] {
            guard let key = parameters["key"] as? String, !key.isEmpty else {
                return BridgeResponse.error(code: "INVALID_PARAMETERS", message: "key is required")
            }

            var query = WuninsuSecureStorageFunctions.query(for: key)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne

            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)

            switch status {
            case errSecSuccess:
                guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
                    return BridgeResponse.error(code: "FAILED", message: "The stored value could not be decoded.")
                }

                return BridgeResponse.success(data: ["status": "found", "value": value])
            case errSecItemNotFound:
                return BridgeResponse.success(data: ["status": "not_found"])
            case errSecInteractionNotAllowed:
                return BridgeResponse.error(code: "UNAVAILABLE", message: "The value cannot be read while the device is locked.")
            default:
                return BridgeResponse.error(code: "FAILED", message: "The value could not be read (\(status)).")
            }
        }
    }

    // MARK: - WuninsuSecureStorage.Set

    /// Parameters: key (string), value (string)
    /// Returns: {success: true}
    class Set: BridgeFunction {
        func execute(parameters: [String: Any]) throws -> [String: Any] {
            guard let key = parameters["key"] as? String, !key.isEmpty else {
                return BridgeResponse.error(code: "INVALID_PARAMETERS", message: "key is required")
            }

            guard let value = parameters["value"] as? String else {
                return BridgeResponse.error(code: "INVALID_PARAMETERS", message: "value is required")
            }

            let query = WuninsuSecureStorageFunctions.query(for: key)
            let attributes: [String: Any] = [
                kSecValueData as String: Data(value.utf8),
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            ]

            var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)

            if status == errSecItemNotFound {
                status = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil)
            }

            guard status == errSecSuccess else {
                return BridgeResponse.error(code: "FAILED", message: "The value could not be stored (\(status)).")
            }

            return BridgeResponse.success(data: ["success": true])
        }
    }

    // MARK: - WuninsuSecureStorage.Delete

    /// Parameters: key (string)
    /// Returns: {success: true}, also when nothing was stored
    class Delete: BridgeFunction {
        func execute(parameters: [String: Any]) throws -> [String: Any] {
            guard let key = parameters["key"] as? String, !key.isEmpty else {
                return BridgeResponse.error(code: "INVALID_PARAMETERS", message: "key is required")
            }

            let status = SecItemDelete(WuninsuSecureStorageFunctions.query(for: key) as CFDictionary)

            guard status == errSecSuccess || status == errSecItemNotFound else {
                return BridgeResponse.error(code: "FAILED", message: "The value could not be deleted (\(status)).")
            }

            return BridgeResponse.success(data: ["success": true])
        }
    }

    // MARK: - Helpers

    /// Items are scoped to this app's bundle id, so two apps using this plugin never share values.
    static func query(for key: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: (Bundle.main.bundleIdentifier ?? "app") + ".wuninsu.securestorage",
            kSecAttrAccount as String: key,
        ]
    }
}
