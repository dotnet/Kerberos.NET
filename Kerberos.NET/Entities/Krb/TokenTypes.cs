// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET
{
    [Flags]
    public enum TokenTypes
    {
        Full = 0x00000000,
        Restricted = 0x000000001
    }
}