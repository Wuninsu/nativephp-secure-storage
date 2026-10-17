<?php

namespace Wuninsu\NativeSecureStorage;

use Illuminate\Support\ServiceProvider;

class SecureStorageServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(SecureStorage::class);
    }
}
