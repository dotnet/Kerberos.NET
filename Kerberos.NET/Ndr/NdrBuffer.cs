// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Ndr
{
    /*
        NDR is a complicated wire format that works by special ordering of types by the
        meta-properties of the structures.

        The NDR format can be found here:
        https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm

        The Windows extensions to NDR for RPC can be found here:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15

        The gist of the format is that fixed-length structures or types are marshalled first
        followed by variable-length arrays and structures. Structures within structures are
        marshalled the same way, but certain variable-length structures are appended outside
        the enclosing struct.

        This marshaller works by stacking IO operations for each struct, reading fixed length,
        and deferring variable operations until the stack frame has finished the operations.
    */

    public interface INdrUnion
    {
        void UnmarshalUnion(NdrBuffer buffer);

        void MarshalUnion(NdrBuffer buffer);
    }

    public interface INdrConformantStruct : INdrStruct
    {
        void MarshalConformance(NdrBuffer buffer);

        void UnmarshalConformance(NdrBuffer buffer);
    }

    public interface INdrStruct
    {
        void Marshal(NdrBuffer buffer);

        void Unmarshal(NdrBuffer buffer);
    }

    [DebuggerDisplay("{Offset} / {backingBuffer.Length} ({BytesAvailable})")]
    public partial class NdrBuffer
    {
        public NdrBuffer(bool align = true)
        {
            this.IsAligned = align;
        }

        private readonly DeferralStack deferrals = new DeferralStack();

        private Memory<byte> backingBuffer;
        private Memory<byte> workingBuffer;

        public bool IsAligned { get; }

        public int Offset { get; private set; }

        public int BytesAvailable => this.workingBuffer.Length;

        public void DebugBuffer() => Hex.Debug(this.workingBuffer.ToArray());

        public void Skip(int length) => this.MoveByOffset(length);

        private void Align(int mask)
        {
            if (!this.IsAligned)
            {
                return;
            }

            var shift = this.Offset & mask - 1;

            if (mask != 0 && shift != 0)
            {
                var seek = mask - shift;

                if (seek > 0)
                {
                    this.MoveByOffset(seek);
                }
            }
        }

        private unsafe ReadOnlySpan<byte> MoveByPrimitiveTypeSize<T>()
           where T : unmanaged
        {
            var size = sizeof(T);

            this.Align(size);

            return this.MoveByOffset(size).Span;
        }

        private Memory<byte> MoveByOffset(int offset)
        {
            if (offset > this.workingBuffer.Length)
            {
                throw new ArgumentException($"Offset {offset} greater than buffer length {this.workingBuffer.Length}", nameof(offset));
            }

            var current = this.workingBuffer.Slice(0);

            this.Offset += offset;

            this.workingBuffer = this.backingBuffer.Slice(this.Offset);

            return current;
        }

        private static int SizeOf<T>()
            where T : struct
        {
            int size;

            if (typeof(T) == typeof(char))
            {
                size = sizeof(char);
            }
            else
            {
                size = Marshal.SizeOf<T>();
            }

            return size;
        }
    }
}
