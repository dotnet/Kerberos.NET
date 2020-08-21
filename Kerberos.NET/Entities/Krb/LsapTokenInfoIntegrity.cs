// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Kerberos.NET
{
    public class LsapTokenInfoIntegrity
    {
        public LsapTokenInfoIntegrity(ReadOnlyMemory<byte> value)
        {
            this.Flags = (TokenTypes)BinaryPrimitives.ReadInt32LittleEndian(value.Span);
            this.TokenIntegrityLevel = (IntegrityLevels)BinaryPrimitives.ReadInt32LittleEndian(value.Span.Slice(4, 4));

            this.MachineId = new ReadOnlySequence<byte>(value.Slice(8, 32));
        }

        public TokenTypes Flags { get; }

        public IntegrityLevels TokenIntegrityLevel { get; }

        public ReadOnlySequence<byte> MachineId { get; }
    }
}