// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{Length}/{MaxLength} {Buffer}")]
    public class RpcString : INdrStruct
    {
        public static readonly RpcString Empty = new();

        public short Length { get; private set; }

        public short MaxLength { get; private set; }

        public ReadOnlyMemory<char> Buffer { get; set; }

        public bool IsNullTerminating => IsNullTerminated(this.Buffer);

        private static bool IsNullTerminated(ReadOnlyMemory<char> buffer)
        {
            if (buffer.Length <= 0)
            {
                return false;
            }

            return buffer.Span[buffer.Length - 1] == '\0';
        }

        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.Length = (short)(this.Buffer.Length * sizeof(char));
            this.MaxLength = (short)(this.Buffer.Length * sizeof(char));

            if (this.IsNullTerminating)
            {
                this.Length -= sizeof(char);
            }

            buffer.WriteInt16LittleEndian(this.Length);
            buffer.WriteInt16LittleEndian(this.MaxLength);

            buffer.WriteDeferredConformantVaryingArray(this.Buffer);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.Length = buffer.ReadInt16LittleEndian();
            this.MaxLength = buffer.ReadInt16LittleEndian();

            buffer.ReadDeferredConformantVaryingArray<char>(v => this.Buffer = v);
        }

        public override string ToString()
        {
            return this.Buffer.Span.ToString();
        }

        public static implicit operator string(RpcString str)
        {
            return str?.ToString();
        }

        public static implicit operator RpcString(string str)
        {
            if (str is null)
            {
                return Empty;
            }

            var mem = str.AsMemory();

            return new RpcString
            {
                Length = (short)(mem.Length * sizeof(char)),
                MaxLength = (short)(mem.Length * sizeof(char)),
                Buffer = mem
            };
        }

        public override bool Equals(object obj)
        {
            if (obj is RpcString rpcStr)
            {
                return string.Equals(rpcStr.ToString(), this.ToString(), StringComparison.Ordinal);
            }

            if (obj is string str)
            {
                return string.Equals(str.ToString(), this.ToString(), StringComparison.Ordinal);
            }

            return base.Equals(obj);
        }

        public override int GetHashCode()
        {
            return this.ToString().GetHashCode();
        }

        public string ExcludeTermination()
        {
            if (this.IsNullTerminating)
            {
                return this.Buffer.Span.Slice(0, this.Buffer.Span.IndexOf('\0')).ToString();
            }

            return this.ToString();
        }
    }
}