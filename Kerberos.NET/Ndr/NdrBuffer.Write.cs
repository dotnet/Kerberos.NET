using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Kerberos.NET.Ndr
{
    public partial class NdrBuffer
    {
        private int referent = 0x20000;

        private IMemoryOwner<byte> rental;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Span<byte> MoveWriteHead(int length)
        {
            EnsureBufferCapacity(length);

            return MoveByOffset(length).Span;
        }

        private void EnsureBufferCapacity(int nextWriteSize)
        {
            if (nextWriteSize < 0)
            {
                throw new OverflowException();
            }

            if (backingBuffer.Length == 0 || backingBuffer.Length - Offset < nextWriteSize)
            {
                const int BlockSize = 1024;

                int blocks = checked(Offset + nextWriteSize + (BlockSize - 1)) / BlockSize;

                var oldBytes = backingBuffer;

                var newRental = CryptoPool.Rent<byte>(BlockSize * blocks);

                backingBuffer = newRental.Memory;

                if (oldBytes.Length > 0)
                {
                    oldBytes.CopyTo(backingBuffer);
                    rental.Dispose();
                }

                rental = newRental;
            }

            MoveByOffset(0);
        }

        public ReadOnlySpan<byte> ToSpan()
        {
            return ToArray();
        }

        private byte[] ToArray()
        {
            var final = new byte[Offset];

            backingBuffer.Slice(0, Offset).CopyTo(final);

            if (rental != null)
            {
                rental.Dispose();
            }

            return final;
        }

        public void WriteMemory(ReadOnlyMemory<byte> memory)
        {
            WriteSpan(memory.Span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void WriteSpan(ReadOnlySpan<byte> val)
        {
            val.CopyTo(MoveWriteHead(val.Length));
        }

        public void WriteByte(byte val)
        {
            MoveWriteHead(1)[0] = val;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe Span<byte> MoveWriteHeadByPrimitiveTypeSize<T>()
           where T : unmanaged
        {
            var size = sizeof(T);

            Align(size);

            return MoveWriteHead(size);
        }

        public void WriteInt16LittleEndian(short value)
        {
            BinaryPrimitives.WriteInt16LittleEndian(MoveWriteHeadByPrimitiveTypeSize<short>(), value);
        }

        public void WriteInt32LittleEndian(int value)
        {
            BinaryPrimitives.WriteInt32LittleEndian(MoveWriteHeadByPrimitiveTypeSize<int>(), value);
        }

        internal void MarshalObject(INdrStruct thing)
        {
            RpcHeader.WriteHeader(this);

            if (WriteDeferred(thing, out _))
            {
                WriteStruct(thing);
            }

            var typeLength = Offset - RpcHeader.HeaderLength;

            BinaryPrimitives.WriteInt32LittleEndian(backingBuffer.Span.Slice(8, 4), typeLength);
        }

        public void WriteStruct<T>(T thing)
            where T : INdrStruct
        {
            using (deferrals.Push())
            {
                thing.Marshal(this);
            }
        }

        public void WriteDeferredStructArray<T>(IEnumerable<T> array)
            where T : INdrStruct
        {
            if (WriteDeferred(array, out _))
            {
                deferrals.Defer(() => WriteConformantArray(array));
            }
        }

        private void WriteConformantArray<T>(IEnumerable<T> array)
            where T : INdrStruct
        {
            WriteInt32LittleEndian(array.Count());

            foreach (var thing in array)
            {
                thing.Marshal(this);
            }
        }

        private void WriteConformantPrimitiveArray<T>(T[] array)
            where T : struct
        {
            WriteInt32LittleEndian(array.Length);

            WriteFixedPrimitiveArray(array);
        }

        private bool WriteDeferred<T>(T thing, out int refer)
        {
            refer = 0;

            if (thing == null)
            {
                WriteInt32LittleEndian(0);
                return false;
            }

            refer = referent;

            WriteInt32LittleEndian(refer);

            referent += sizeof(int);

            return true;
        }

        private bool WriteDeferred<T>(ReadOnlyMemory<T> mem)
        {
            return WriteDeferred(mem.Span);
        }

        private bool WriteDeferred<T>(ReadOnlySpan<T> span)
        {
            if (span.Length == 0)
            {
                WriteInt32LittleEndian(0);
                return false;
            }

            WriteInt32LittleEndian(referent);

            referent += sizeof(int);
            return true;
        }

        public void WriteDeferredStructUnion<T>(T thing)
            where T : INdrUnion
        {
            if (WriteDeferred(thing, out int referent))
            {
                deferrals.Defer(() => thing.MarshalUnion(this));
            }
        }

        public void WriteDeferredStruct<T>(T thing)
            where T : INdrStruct
        {
            if (WriteDeferred(thing, out int referent))
            {
                deferrals.Defer(() => WriteReferentStruct(thing, referent));
            }
        }

        public void WriteReferentStruct<T>(T thing, int referent)
            where T : INdrStruct
        {
            if (referent > 0)
            {
                WriteInt32LittleEndian(referent);

                WriteStruct(thing);
            }
        }

        public void WriteFixedPrimitiveArray<T>(T[] value)
            where T : struct
        {
            Align(SizeOf<T>());

            var write = MemoryMarshal.Cast<T, byte>(value);

            WriteSpan(write);
        }

        public void WriteDeferredConformantVaryingArray<T>(ReadOnlyMemory<T> buffer)
            where T : struct
        {
            if (WriteDeferred(buffer))
            {
                deferrals.Defer(() => WriteConformantVaryingArray(buffer.Span));
            }
        }

        public void WriteConformantVaryingArray<T>(ReadOnlySpan<T> array)
            where T : struct
        {
            if (typeof(T) == typeof(char))
            {
                WriteConformantVaryingCharArray(MemoryMarshal.Cast<T, char>(array));
            }
        }

        private void WriteConformantVaryingCharArray(ReadOnlySpan<char> span)
        {
            WriteInt32LittleEndian(span.Length);
            WriteInt32LittleEndian(0);
            WriteInt32LittleEndian(span.Length);

            WriteSpan(MemoryMarshal.Cast<char, byte>(span));
        }

        public void WriteDeferredConformantArray<T>(ReadOnlySpan<T> span)
            where T : struct
        {
            if (WriteDeferred(span))
            {
                var deferred = span.ToArray();

                deferrals.Defer(() => WriteConformantPrimitiveArray(deferred));
            }
        }

        public void WriteDeferredArray<T>(IEnumerable<T> array, Action<T> action)
        {
            foreach (var val in array)
            {
                if (WriteDeferred(val, out _))
                {
                    deferrals.Defer(() => action(val));
                }
            }
        }
    }
}
