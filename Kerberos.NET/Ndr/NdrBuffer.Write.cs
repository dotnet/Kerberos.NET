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
        private readonly bool fixedSize;

        private int referent = 0x20000;
        private IMemoryOwner<byte> rental;

        public NdrBuffer(Memory<byte> memory, bool align = true)
            : this(align)
        {
            fixedSize = true;

            backingBuffer = memory;

            MoveByOffset(0);
        }

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

        public Memory<byte> ToMemory(int alignment) => ToArray(alignment);

        public Span<byte> ToSpan(int alignment = 0) => ToArray(alignment);

        private byte[] ToArray(int alignment)
        {
            Align(alignment);

            var final = new byte[fixedSize ? backingBuffer.Length : Offset];

            backingBuffer.Slice(0, final.Length).CopyTo(final);

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

        public void WriteSpan(ReadOnlySpan<byte> val, int offset)
        {
            val.CopyTo(backingBuffer.Span.Slice(offset));
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

        public void WriteUInt32LittleEndian(uint value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(MoveWriteHeadByPrimitiveTypeSize<int>(), value);
        }

        public void WriteInt64LittleEndian(long value)
        {
            BinaryPrimitives.WriteInt64LittleEndian(MoveWriteHeadByPrimitiveTypeSize<long>(), value);
        }

        internal void MarshalObject(INdrStruct thing)
        {
            RpcHeader.WriteHeader(this);

            if (WriteDeferred(thing))
            {
                WriteStruct(thing);
            }

            Align(8);

            var typeLength = Offset - RpcHeader.HeaderLength;

            BinaryPrimitives.WriteInt32LittleEndian(backingBuffer.Span.Slice(8, 4), typeLength);
        }

        public void WriteStruct<T>(T thing)
            where T : INdrStruct
        {
            using (deferrals.Push())
            {
                if (thing is INdrConformantStruct conformantStruct)
                {
                    conformantStruct.MarshalConformance(this);
                }

                thing.Marshal(this);
            }
        }

        public void WriteDeferredStructArray<T>(IEnumerable<T> array)
            where T : INdrStruct
        {
            if (WriteDeferred(array))
            {
                deferrals.Defer(() => WriteConformantArray(array, referent));
            }
        }

        public void WriteDeferredConformantStructArray<T>(IEnumerable<T> array)
            where T : INdrConformantStruct
        {
            if (WriteDeferred(array))
            {
                var referral = referent;

                IncrementReferent(array.Count() * sizeof(int));

                deferrals.Defer(() => WriteConformantArray(array, referral));
            }
        }

        private void WriteConformantArray<T>(IEnumerable<T> array, int referral)
            where T : INdrStruct
        {
            referent = referral;

            WriteInt32LittleEndian(array.Count());

            foreach (var thing in array)
            {
                thing.Marshal(this);
            }
        }

        private void WriteConformantPrimitiveArray<T>(ReadOnlySpan<T> array)
            where T : struct
        {
            WriteInt32LittleEndian(array.Length);

            WriteFixedPrimitiveArray(array);
        }

        internal void IncrementReferent(int size)
        {
            referent += size;
        }

        private bool WriteDeferred(bool write)
        {
            if (!write)
            {
                WriteInt32LittleEndian(0);
                return false;
            }

            WriteInt32LittleEndian(referent);

            referent += sizeof(int);

            return true;
        }

        private bool WriteDeferred<T>(T thing)
        {
            return WriteDeferred(thing != null);
        }

        private bool WriteDeferred()
        {
            return WriteDeferred(true);
        }

        public void WriteDeferredStructUnion<T>(T thing)
            where T : INdrUnion
        {
            if (WriteDeferred(thing))
            {
                deferrals.Defer(() => thing.MarshalUnion(this));
            }
        }

        public void WriteConformantStruct<T>(T thing)
            where T : INdrStruct
        {
            if (WriteDeferred(thing))
            {
                deferrals.Defer(() => WriteReferentStruct(thing));
            }
        }

        private void WriteReferentStruct<T>(T thing)
            where T : INdrStruct
        {
            WriteStruct(thing);
        }

        public void WriteFixedPrimitiveArray<T>(ReadOnlySpan<T> value)
            where T : struct
        {
            Align(SizeOf<T>());

            var write = MemoryMarshal.Cast<T, byte>(value);

            WriteSpan(write);
        }

        public void WriteDeferredConformantVaryingArray<T>(ReadOnlyMemory<T> buffer)
            where T : struct
        {
            if (WriteDeferred())
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

        private void WriteConformantVaryingCharArray(ReadOnlySpan<char> chars)
        {
            var indexOfNull = chars.IndexOf('\0');

            var charWrite = chars;

            if (indexOfNull > 0)
            {
                charWrite = chars.Slice(0, indexOfNull);
            }

            var bytes = MemoryMarshal.Cast<char, byte>(charWrite);

            WriteInt32LittleEndian(chars.Length);
            WriteInt32LittleEndian(0);
            WriteInt32LittleEndian(charWrite.Length);

            WriteSpan(bytes);
        }

        public void WriteDeferredConformantArray<T>(ReadOnlySpan<T> span)
            where T : struct
        {
            if (WriteDeferred())
            {
                var deferred = span.ToArray();

                deferrals.Defer(() => WriteConformantPrimitiveArray<T>(deferred));
            }
        }

        public void WriteDeferredArray<T>(IEnumerable<T> array, Action<T> action)
        {
            foreach (var val in array)
            {
                if (WriteDeferred(val))
                {
                    deferrals.Defer(() => action(val));
                }
            }
        }
    }
}
