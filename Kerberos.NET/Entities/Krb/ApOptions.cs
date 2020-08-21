// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum ApOptions
    {
        Reserved = 0,
        ChannelBindingSupported = 1 << 14,
        UseSessionKey = 1 << 30,
        MutualRequired = 1 << 29
    }
}