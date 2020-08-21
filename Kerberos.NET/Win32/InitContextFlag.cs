﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Win32
{
    [Flags]
    internal enum InitContextFlag
    {
        Zero = 0,
        Delegate = 0x00000001,
        MutualAuth = 0x00000002,
        ReplayDetect = 0x00000004,
        SequenceDetect = 0x00000008,
        Confidentiality = 0x00000010,
        UseSessionKey = 0x00000020,
        AllocateMemory = 0x00000100,
        Connection = 0x00000800,
        InitExtendedError = 0x00004000,
        InitStream = 0x00008000,
        InitIntegrity = 0x00010000,
        InitManualCredValidation = 0x00080000,
        InitUseSuppliedCreds = 0x00000080,
        InitIdentify = 0x00020000,
        ProxyBindings = 0x04000000,
        AllowMissingBindings = 0x10000000,
        UnverifiedTargetName = 0x20000000
    }
}