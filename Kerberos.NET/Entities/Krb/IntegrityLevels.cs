// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET
{
    [Flags]
    public enum IntegrityLevels
    {
        Untrusted = 0x00000000,
        Low = 0x00001000,
        Medium = 0x00002000,
        High = 0x00003000,
        System = 0x00004000,
        ProtectedProcess = 0x00005000
    }
}