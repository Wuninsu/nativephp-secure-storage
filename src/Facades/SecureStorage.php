<?php

namespace Wuninsu\NativeSecureStorage\Facades;

use Illuminate\Support\Facades\Facade;
use Wuninsu\NativeSecureStorage\SecureStorageResult;

/**
 * @method static bool isAvailable()
 * @method static string|null get(string $key)
 * @method static SecureStorageResult read(string $key)
 * @method static bool set(string $key, string $value)
 * @method static bool delete(string $key)
 *
 * @see \Wuninsu\NativeSecureStorage\SecureStorage
 */
class SecureStorage extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Wuninsu\NativeSecureStorage\SecureStorage::class;
    }
}
