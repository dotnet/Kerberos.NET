using Kerberos.NET.Crypto;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
        public void UnmarshalUnion(NdrBuffer buffer);

        public void MarshalUnion(NdrBuffer buffer);
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
            IsAligned = align;
        }

        private readonly DeferralStack deferrals = new DeferralStack();

        private Memory<byte> backingBuffer;
        private Memory<byte> workingBuffer;

        public bool IsAligned { get; }

        public int Offset { get; private set; }

        public int BytesAvailable => workingBuffer.Length;

        public void DebugBuffer() => Hex.Debug(workingBuffer.ToArray());

        public void Skip(int length) => MoveByOffset(length);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Align(int mask)
        {
            if (!IsAligned)
            {
                return;
            }

            var shift = Offset & mask - 1;

            if (mask != 0 && shift != 0)
            {
                var seek = mask - shift;

                if (seek > 0)
                {
                    MoveByOffset(seek);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe ReadOnlySpan<byte> MoveByPrimitiveTypeSize<T>()
           where T : unmanaged
        {
            var size = sizeof(T);

            Align(size);

            return MoveByOffset(size).Span;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Memory<byte> MoveByOffset(int offset)
        {
            if (offset > workingBuffer.Length)
            {
                throw new ArgumentException($"Offset {offset} greater than buffer length {workingBuffer.Length}", nameof(offset));
            }

            var current = workingBuffer.Slice(0);

            Offset += offset;

            workingBuffer = backingBuffer.Slice(Offset);

            return current;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int SizeOf<T>() where T : struct
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
