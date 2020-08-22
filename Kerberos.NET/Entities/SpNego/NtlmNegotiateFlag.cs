// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

#pragma warning disable CA1714 // Flags enums should have plural names

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum NtlmNegotiateFlag
    {
        NTLMSSP_NEGOTIATE_56 = 1 << 31,
        NTLMSSP_NEGOTIATE_KEY_EXCH = 1 << 30,
        NTLMSSP_NEGOTIATE_128 = 1 << 29,
        R1 = 1 << 28,
        R2 = 1 << 27,
        R3 = 1 << 26,
        NTLMSSP_NEGOTIATE_VERSION = 1 << 25,
        R4 = 1 << 24,
        NTLMSSP_NEGOTIATE_TARGET_INFO = 1 << 23,
        NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 1 << 22,
        R5 = 1 << 21,
        NTLMSSP_NEGOTIATE_IDENTIFY = 1 << 20,
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 1 << 19,
        R6 = 1 << 18,
        NTLMSSP_TARGET_TYPE_SERVER = 1 << 17,
        NTLMSSP_TARGET_TYPE_DOMAIN = 1 << 16,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 1 << 15,
        R7 = 1 << 14,
        NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 1 << 13,
        NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 1 << 12,
        NTLMSSP_NEGOTIATE_ANONYMOUS_CONNECTION = 1 << 11,
        R8 = 1 << 10,
        NTLMSSP_NEGOTIATE_NTLM_V1 = 1 << 9,
        R9 = 1 << 8,
        NTLMSSP_NEGOTIATE_LM_KEY = 1 << 7,
        NTLMSSP_NEGOTIATE_DATAGRAM = 1 << 6,
        NTLMSSP_NEGOTIATE_SEAL = 1 << 5,
        NTLMSSP_NEGOTIATE_SIGN = 1 << 4,
        R10 = 1 << 3,
        NTLMSSP_REQUEST_TARGET = 1 << 2,
        NTLM_NEGOTIATE_OEM = 1 << 1,
        NTLMSSP_NEGOTIATE_UNICODE = 1 << 0
    }
}