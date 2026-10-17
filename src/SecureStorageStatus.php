<?php

namespace Wuninsu\NativeSecureStorage;

enum SecureStorageStatus: string
{
    /** A value is stored under the key. */
    case Found = 'found';

    /** Nothing is stored under the key. */
    case NotFound = 'not_found';

    /** A value may exist but cannot be read right now (iOS: the phone is locked). */
    case Unavailable = 'unavailable';

    /** The read failed: no plugin, no bridge, or a native error. */
    case Failed = 'failed';
}
