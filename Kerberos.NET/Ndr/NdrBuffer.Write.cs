// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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
    /// <summary>
    /// A buffer used to serialize NDR message structures.
    /// </summary>
    public partial class NdrBuffer : IDisposable
    {
        private readonly bool fixedSize;

        private int referent = 0x20000;
        private IMemoryOwner<byte> rental;
        private bool disposedValue;

        public NdrBuffer(Memory<byte> memory, bool align = true)
            : this(align)
        {
            this.fixedSize = true;

            this.backingBuffer = memory;

            this.MoveByOffset(0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private Span<byte> MoveWriteHead(int length)
        {
            this.EnsureBufferCapacity(length);

            return this.MoveByOffset(length).Span;
        }

        private void EnsureBufferCapacity(int nextWriteSize)
        {
            if (nextWriteSize < 0)
            {
                throw new OverflowException();
            }

            if (this.backingBuffer.Length == 0 || this.backingBuffer.Length - this.Offset < nextWriteSize)
            {
                const int BlockSize = 1024;

                int blocks = checked(this.Offset + nextWriteSize + (BlockSize - 1)) / BlockSize;

                var oldBytes = this.backingBuffer;

                var newRental = CryptoPool.Rent<byte>(BlockSize * blocks);

                this.backingBuffer = newRental.Memory;

                if (oldBytes.Length > 0)
                {
                    oldBytes.CopyTo(this.backingBuffer);
                    this.rental.Dispose();
                }

                this.rental = newRental;
            }

            this.MoveByOffset(0);
        }

        public Memory<byte> ToMemory(int alignment) => this.ToArray(alignment);

        public Memory<byte> ToMemory() => this.ToMemory(0);

        public Span<byte> ToSpan(int alignment = 0) => this.ToArray(alignment);

        private byte[] ToArray(int alignment)
        {
            this.Align(alignment);

            var final = new byte[this.fixedSize ? this.backingBuffer.Length : this.Offset];

            this.backingBuffer.Slice(0, final.Length).CopyTo(final);

            return final;
        }

        public void WriteMemory(ReadOnlyMemory<byte> memory)
        {
            this.WriteSpan(memory.Span);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void WriteSpan(ReadOnlySpan<byte> val)
        {
            val.CopyTo(this.MoveWriteHead(val.Length));
        }

        public void WriteSpan(ReadOnlySpan<byte> val, int offset)
        {
            val.CopyTo(this.backingBuffer.Span.Slice(offset));
        }

        public void WriteByte(byte val)
        {
            this.MoveWriteHead(1)[0] = val;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe Span<byte> MoveWriteHeadByPrimitiveTypeSize<T>()
           where T : unmanaged
        {
            var size = sizeof(T);

            this.Align(size);

            return this.MoveWriteHead(size);
        }

        public void WriteInt16LittleEndian(short value)
        {
            BinaryPrimitives.WriteInt16LittleEndian(this.MoveWriteHeadByPrimitiveTypeSize<short>(), value);
        }

        public void WriteInt16BigEndian(short value)
        {
            BinaryPrimitives.WriteInt16BigEndian(this.MoveWriteHeadByPrimitiveTypeSize<short>(), value);
        }

        public void WriteInt32LittleEndian(int value)
        {
            BinaryPrimitives.WriteInt32LittleEndian(this.MoveWriteHeadByPrimitiveTypeSize<int>(), value);
        }

        public void WriteInt32BigEndian(int value)
        {
            BinaryPrimitives.WriteInt32BigEndian(this.MoveWriteHeadByPrimitiveTypeSize<int>(), value);
        }

        public void WriteUInt32LittleEndian(uint value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(this.MoveWriteHeadByPrimitiveTypeSize<int>(), value);
        }

        public void WriteInt64LittleEndian(long value)
        {
            BinaryPrimitives.WriteInt64LittleEndian(this.MoveWriteHeadByPrimitiveTypeSize<long>(), value);
        }

        internal void MarshalObject(INdrStruct thing)
        {
            RpcHeader.WriteHeader(this);

            if (this.WriteDeferred(thing))
            {
                this.WriteStruct(thing);
            }

            this.Align(8);

            var typeLength = this.Offset - RpcHeader.HeaderLength;

            BinaryPrimitives.WriteInt32LittleEndian(this.backingBuffer.Span.Slice(8, 4), typeLength);
        }

        public void WriteStruct<T>(T thing)
            where T : INdrStruct
        {
            using (this.deferrals.Push())
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
            if (this.WriteDeferred(array))
            {
                this.deferrals.Defer(() => this.WriteConformantArray(array, this.referent));
            }
        }

        public void WriteDeferredConformantStructArray<T>(IEnumerable<T> array)
            where T : INdrConformantStruct
        {
            if (this.WriteDeferred(array))
            {
                var referral = this.referent;

                this.IncrementReferent(array.Count() * sizeof(int));

                this.deferrals.Defer(() => this.WriteConformantArray(array, referral));
            }
        }

        private void WriteConformantArray<T>(IEnumerable<T> array, int referral)
            where T : INdrStruct
        {
            this.referent = referral;

            this.WriteInt32LittleEndian(array.Count());

            foreach (var thing in array)
            {
                thing.Marshal(this);
            }
        }

        private void WriteConformantPrimitiveArray<T>(ReadOnlySpan<T> array)
            where T : struct
        {
            this.WriteInt32LittleEndian(array.Length);

            this.WriteFixedPrimitiveArray(array);
        }

        internal void IncrementReferent(int size)
        {
            this.referent += size;
        }

        private bool WriteDeferred(bool write)
        {
            if (!write)
            {
                this.WriteInt32LittleEndian(0);
                return false;
            }

            this.WriteInt32LittleEndian(this.referent);

            this.referent += sizeof(int);

            return true;
        }

        private bool WriteDeferred<T>(T thing)
        {
            return this.WriteDeferred(thing != null);
        }

        private bool WriteDeferred()
        {
            return this.WriteDeferred(true);
        }

        public void WriteDeferredStructUnion<T>(T thing)
            where T : INdrUnion
        {
            if (this.WriteDeferred(thing))
            {
                this.deferrals.Defer(() => thing.MarshalUnion(this));
            }
        }

        public void WriteConformantStruct<T>(T thing)
            where T : INdrStruct
        {
            if (this.WriteDeferred(thing))
            {
                this.deferrals.Defer(() => this.WriteReferentStruct(thing));
            }
        }

        private void WriteReferentStruct<T>(T thing)
            where T : INdrStruct
        {
            this.WriteStruct(thing);
        }

        public void WriteFixedPrimitiveArray<T>(ReadOnlySpan<T> value)
            where T : struct
        {
            this.Align(SizeOf<T>());

            var write = MemoryMarshal.Cast<T, byte>(value);

            this.WriteSpan(write);
        }

        public void WriteDeferredConformantVaryingArray<T>(ReadOnlyMemory<T> buffer)
            where T : struct
        {
            if (this.WriteDeferred())
            {
                this.deferrals.Defer(() => this.WriteConformantVaryingArray(buffer.Span));
            }
        }

        public void WriteConformantVaryingArray<T>(ReadOnlySpan<T> array)
            where T : struct
        {
            if (typeof(T) == typeof(char))
            {
                this.WriteConformantVaryingCharArray(MemoryMarshal.Cast<T, char>(array));
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

            this.WriteInt32LittleEndian(chars.Length);
            this.WriteInt32LittleEndian(0);
            this.WriteInt32LittleEndian(charWrite.Length);

            this.WriteSpan(bytes);
        }

        public void WriteDeferredConformantArray<T>(ReadOnlySpan<T> span)
            where T : struct
        {
            if (this.WriteDeferred())
            {
                var deferred = span.ToArray();

                this.deferrals.Defer(() => this.WriteConformantPrimitiveArray<T>(deferred));
            }
        }

        public void WriteDeferredArray<T>(IEnumerable<T> array, Action<T> action)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            foreach (var val in array)
            {
                if (this.WriteDeferred(val))
                {
                    this.deferrals.Defer(() => action(val));
                }
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                if (disposing)
                {
                    this.rental?.Dispose();
                    this.deferrals.Dispose();
                }

                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
