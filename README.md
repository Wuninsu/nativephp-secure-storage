# NativePHP Secure Storage

Keep small secrets, such as an API token, in the **iOS Keychain** or the **Android Keystore** from a NativePHP Mobile v4 app.

- **iOS:** Keychain generic-password items, readable only while the phone is unlocked, never synced to iCloud or included in backups (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
- **Android:** AES-256-GCM, with the key held in the Android Keystore (hardware-backed where the phone has it). The ciphertext is stored in `noBackupFilesDir`, so it is never part of a backup.

Values stay on the device they were written on. They do not move to a new phone, and are gone after a reinstall.

Use it for small text values (a few KB at most).

## Install

From a local folder (Composer path repository):

```json
"repositories": [
    { "type": "path", "url": "packages/nativephp-secure-storage" }
]
```

```sh
composer require wuninsu/nativephp-secure-storage:@dev
php artisan native:plugin:register wuninsu/nativephp-secure-storage
php artisan native:install --force
```

Requires `nativephp/mobile` ^4.6, Android 8 (API 26) or newer, iOS 18.2 or newer.

## Use

```php
use Wuninsu\NativeSecureStorage\Facades\SecureStorage;

SecureStorage::set('api_token', $token);   // true on success
SecureStorage::get('api_token');           // string, or null
SecureStorage::delete('api_token');        // true, also when nothing was stored
```

`get()` returns null for every miss. When the reason matters, use `read()`:

```php
use Wuninsu\NativeSecureStorage\SecureStorageStatus;

$result = SecureStorage::read('api_token');

match ($result->status) {
    SecureStorageStatus::Found => $result->value,
    SecureStorageStatus::NotFound => null,       // nothing stored
    SecureStorageStatus::Unavailable => null,    // iOS: the phone is locked; try again later
    SecureStorageStatus::Failed => null,         // no plugin, no bridge, or a native error ($result->code)
};
```

Keys are 1 to 255 characters. A value that can no longer be decrypted (for example after the Keystore key was reset) is deleted and reads as not found.

### Only on the phone

The plugin's native code exists only in a real build (`php artisan native:run` or a release). It is **not** in the NativePHP Jump app, and there is no bridge on a web server or in tests. Check before relying on it:

```php
if (SecureStorage::isAvailable()) {
    // inside a built app that contains this plugin
}
```

## Testing

Fake the bridge with NativePHP's `FakeBridge`:

```php
use Native\Mobile\Testing\FakeBridge;

FakeBridge::enable()
    ->respondTo('WuninsuSecureStorage.Get', ['status' => 'found', 'value' => 'secret'])
    ->respondTo('WuninsuSecureStorage.Set', ['success' => true]);
```

## Bridge functions

| Function | Parameters | Returns |
|---|---|---|
| `WuninsuSecureStorage.Get` | `key` | `{status: "found", value}` or `{status: "not_found"}` |
| `WuninsuSecureStorage.Set` | `key`, `value` | `{success: true}` |
| `WuninsuSecureStorage.Delete` | `key` | `{success: true}` |

Errors use NativePHP's envelope: `{status: "error", code, message}`. `code` is `UNAVAILABLE` when iOS refuses because the phone is locked, otherwise `FAILED` or `INVALID_PARAMETERS`.

## License

MIT
