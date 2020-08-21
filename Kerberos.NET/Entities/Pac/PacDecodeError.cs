// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    public class PacDecodeError
    {
        public PacType Type { get; set; }

        public ReadOnlyMemory<byte> Data { get; set; }

        public Exception Exception { get; set; }
    }
}