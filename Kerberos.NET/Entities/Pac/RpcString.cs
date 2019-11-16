using Kerberos.NET.Ndr;
using System;
using System.Diagnostics;

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{Length}/{MaxLength} {Buffer}")]
    public class RpcString : INdrStruct
    {
        public static readonly RpcString Empty = new RpcString();

        public short Length { get; private set; }

        public short MaxLength { get; private set; }

        public ReadOnlyMemory<char> Buffer;

        public bool IsNullTerminating => IsNullTerminated(Buffer);

        private bool IsNullTerminated(ReadOnlyMemory<char> buffer)
        {
            if (buffer.Length <= 0)
            {
                return false;
            }

            return buffer.Span[buffer.Length - 1] == '\0';
        }

        public void Marshal(NdrBuffer buffer)
        {
            Length = (short)(Buffer.Length * sizeof(char));
            MaxLength = (short)(Buffer.Length * sizeof(char));

            if (IsNullTerminating)
            {
                Length -= sizeof(char);
            }

            buffer.WriteInt16LittleEndian(Length);
            buffer.WriteInt16LittleEndian(MaxLength);

            buffer.WriteDeferredConformantVaryingArray(Buffer);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            Length = buffer.ReadInt16LittleEndian();
            MaxLength = buffer.ReadInt16LittleEndian();

            buffer.ReadDeferredConformantVaryingArray<char>(v => Buffer = v);
        }

        public override string ToString()
        {
            return Buffer.Span.ToString();
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
                return string.Equals(rpcStr.ToString(), ToString(), StringComparison.Ordinal);
            }

            if (obj is string str)
            {
                return string.Equals(str.ToString(), ToString(), StringComparison.Ordinal);
            }

            return base.Equals(obj);
        }

        public override int GetHashCode()
        {
            return ToString().GetHashCode();
        }
    }
}
