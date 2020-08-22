// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities.Pac
{
    [Flags]
    public enum UserFlags
    {
        LOGON_GUEST = 1,
        LOGON_NOENCRYPTION = 2,
        LOGON_CACHED_ACCOUNT = 4,
        LOGON_USED_LM_PASSWORD = 8,
        LOGON_EXTRA_SIDS = 32,
        LOGON_SUBAUTH_SESSION_KEY = 64,
        LOGON_SERVER_TRUST_ACCOUNT = 128,
        LOGON_NTLMV2_ENABLED = 256,
        LOGON_RESOURCE_GROUPS = 512,
        LOGON_PROFILE_PATH_RETURNED = 1024,
        LOGON_GRACE_LOGON = 16777216,
        LOGON_NT_V2 = 0x800,
        LOGON_LM_V2 = 0x1000,
        LOGON_NTLM_V2 = 0x2000,
        LOGON_OPTIMIZED = 0x4000,
        LOGON_WINLOGON = 0x8000,
        LOGON_PKINIT = 0x10000,
        LOGON_NO_OPTIMIZED = 0x20000
    }
}