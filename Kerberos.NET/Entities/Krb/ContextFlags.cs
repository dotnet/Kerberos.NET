// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum ContextFlags
    {
        DelegFlag = 1 << 6,
        MutualFlag = 1 << 5,
        ReplayFlag = 1 << 4,
        SequenceFlag = 1 << 3,
        AnonFlag = 1 << 2,
        ConfFlag = 1 << 1,
        IntegFlag = 1 << 0
    }
}