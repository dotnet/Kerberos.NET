// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    public class NegotiateExtension
    {
        public NegotiateExtension(ReadOnlyMemory<byte> data)
        {
            this.Message = new NegotiateMessage(data);
        }

        public NegotiateMessage Message { get; }

        internal static bool CanDecode(ReadOnlyMemory<byte> data)
        {
            return NegotiateMessageHeader.HasHeader(data);
        }
    }
}