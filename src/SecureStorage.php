<?php

namespace Wuninsu\NativeSecureStorage;

use InvalidArgumentException;
use ReflectionFunction;

/**
 * Small secrets in the iOS Keychain or the Android Keystore.
 *
 * Values are bound to this device: they are not included in backups and do not move to a new phone.
 */
class SecureStorage
{
    public const BRIDGE = 'WuninsuSecureStorage';

    /**
     * True only inside a built app that contains this plugin.
     *
     * On a web server, in tests and under `native:jump`, `nativephp_call()` is NativePHP's PHP stand-in, not the
     * device's native function, so this returns false there.
     */
    public function isAvailable(): bool
    {
        if (! function_exists('nativephp_call') || ! (new ReflectionFunction('nativephp_call'))->isInternal()) {
            return false;
        }

        return ! function_exists('nativephp_can') || nativephp_can(self::BRIDGE.'.Get');
    }

    /**
     * The stored value, or null when there is none or it cannot be read.
     */
    public function get(string $key): ?string
    {
        return $this->read($key)->value;
    }

    /**
     * The stored value with the reason when there is none (not stored, phone locked, or failure).
     */
    public function read(string $key): SecureStorageResult
    {
        $this->validateKey($key);

        if (! function_exists('nativephp_call')) {
            return SecureStorageResult::failure('BRIDGE_UNAVAILABLE', 'Secure storage is only available inside a NativePHP app.');
        }

        return SecureStorageResult::fromResponse($this->call('Get', ['key' => $key]));
    }

    /**
     * Store a value, replacing any value under the same key.
     */
    public function set(string $key, string $value): bool
    {
        $this->validateKey($key);

        return ($this->call('Set', ['key' => $key, 'value' => $value])['success'] ?? false) === true;
    }

    /**
     * Delete a value. Deleting a key that holds nothing also succeeds.
     */
    public function delete(string $key): bool
    {
        $this->validateKey($key);

        return ($this->call('Delete', ['key' => $key])['success'] ?? false) === true;
    }

    /**
     * @param  array<string, string>  $parameters
     * @return array<mixed>|null
     */
    private function call(string $function, array $parameters): ?array
    {
        if (! function_exists('nativephp_call')) {
            return null;
        }

        $response = nativephp_call(self::BRIDGE.'.'.$function, json_encode($parameters, JSON_THROW_ON_ERROR));
        $decoded = is_string($response) ? json_decode($response, true) : null;

        return is_array($decoded) ? $decoded : null;
    }

    private function validateKey(string $key): void
    {
        if ($key === '' || strlen($key) > 255) {
            throw new InvalidArgumentException('A secure storage key must be 1 to 255 characters long.');
        }
    }
}
