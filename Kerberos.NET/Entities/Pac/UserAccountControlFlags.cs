// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities.Pac
{
    [Flags]
    public enum UserAccountControlFlags
    {
        ADS_UF_ACCOUNT_DISABLE = 2,
        ADS_UF_HOMEDIR_REQUIRED = 8,
        ADS_UF_LOCKOUT = 16,
        ADS_UF_PASSWD_NOTREQD = 32,
        ADS_UF_PASSWD_CANT_CHANGE = 64,
        ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128,
        ADS_UF_NORMAL_ACCOUNT = 512,
        ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 2048,
        ADS_UF_WORKSTATION_TRUST_ACCOUNT = 4096,
        ADS_UF_SERVER_TRUST_ACCOUNT = 8192,
        ADS_UF_DONT_EXPIRE_PASSWD = 65536,
        ADS_UF_MNS_LOGON_ACCOUNT = 131072,
        ADS_UF_SMARTCARD_REQUIRED = 262144,
        ADS_UF_TRUSTED_FOR_DELEGATION = 524288,
        ADS_UF_NOT_DELEGATED = 1048576,
        ADS_UF_USE_DES_KEY_ONLY = 2097152,
        ADS_UF_DONT_REQUIRE_PREAUTH = 4194304,
        ADS_UF_PASSWORD_EXPIRED = 8388608,
        ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216,
        ADS_UF_NO_AUTH_DATA_REQUIRED = 33554432,
        ADS_UF_PARTIAL_SECRETS_ACCOUNT = 67108864
    }
}