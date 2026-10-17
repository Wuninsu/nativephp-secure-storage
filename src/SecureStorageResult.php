<?php

namespace Wuninsu\NativeSecureStorage;

/**
 * The outcome of a read: the value, or why there is none.
 */
final class SecureStorageResult
{
    public function __construct(
        public readonly SecureStorageStatus $status,
        public readonly ?string $value = null,
        public readonly ?string $code = null,
        public readonly ?string $message = null,
    ) {}

    public static function failure(string $code, string $message): self
    {
        return new self(SecureStorageStatus::Failed, null, $code, $message);
    }

    /**
     * Build a result from the decoded bridge response.
     *
     * Success: {"status": "found", "value": "…"} or {"status": "not_found"}.
     * Error: {"status": "error", "code": "…", "message": "…"}.
     *
     * @param  array<mixed>|null  $response
     */
    public static function fromResponse(?array $response): self
    {
        if ($response === null || $response === []) {
            return self::failure('BRIDGE_UNAVAILABLE', 'The native bridge returned no response.');
        }

        $code = isset($response['code']) ? (string) $response['code'] : null;
        $message = isset($response['message']) ? (string) $response['message'] : null;

        return match ($response['status'] ?? null) {
            'found' => is_string($response['value'] ?? null)
                ? new self(SecureStorageStatus::Found, $response['value'])
                : self::failure('MALFORMED_RESPONSE', 'The native bridge returned no value.'),
            'not_found' => new self(SecureStorageStatus::NotFound),
            'error' => new self($code === 'UNAVAILABLE' ? SecureStorageStatus::Unavailable : SecureStorageStatus::Failed, null, $code, $message),
            default => self::failure('MALFORMED_RESPONSE', 'The native bridge returned an unexpected response.'),
        };
    }

    public function found(): bool
    {
        return $this->status === SecureStorageStatus::Found;
    }
}
