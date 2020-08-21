// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Ndr
{
    public partial class NdrBuffer
    {
        public NdrBuffer(ReadOnlyMemory<byte> memory, bool align = true)
            : this(align)
        {
            this.backingBuffer = MemoryMarshal.AsMemory(memory);

            this.MoveByOffset(0);
        }

        public void UnmarshalObject(INdrStruct thing)
        {
            if (!RpcHeader.TryReadHeader(this, out RpcHeader header))
            {
                throw new InvalidDataException("Expecting a header but got something unknown");
            }

            if (header.Endian != EndianType.Little)
            {
                throw new InvalidDataException("Expecting little endian encoding");
            }

            if (header.ObjectBufferLength > this.BytesAvailable)
            {
                throw new InvalidDataException($"Expected length ({header.ObjectBufferLength} bytes) is greater than available bytes ({this.BytesAvailable} bytes)");
            }

            this.ReadReferentStruct(thing);
        }

        public void ReadDeferredArray(int knownSize, Action op)
        {
            for (var i = 0; i < knownSize; i++)
            {
                this.ReadDeferred(op);
            }
        }

        public ReadOnlyMemory<byte> ReadMemory(int length) => this.MoveByOffset(length).Slice(0, length);

        public ReadOnlySpan<byte> Read(int length) => this.ReadMemory(length).Span;

        public byte ReadByteLittleEndian() => this.MoveByOffset(1).Span[0];

        public short ReadInt16LittleEndian()
        {
            return BinaryPrimitives.ReadInt16LittleEndian(this.MoveByPrimitiveTypeSize<short>());
        }

        public int ReadInt32LittleEndian()
        {
            return BinaryPrimitives.ReadInt32LittleEndian(this.MoveByPrimitiveTypeSize<int>());
        }

        public uint ReadUInt32LittleEndian()
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(this.MoveByPrimitiveTypeSize<uint>());
        }

        public long ReadInt64LittleEndian()
        {
            return BinaryPrimitives.ReadInt64LittleEndian(this.MoveByPrimitiveTypeSize<long>());
        }

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        public ReadOnlySpan<T> ReadFixedPrimitiveArray<T>(int knownLength)
            where T : struct
        {
            if (knownLength == 0)
            {
                return ReadOnlySpan<T>.Empty;
            }

            int size = SizeOf<T>();

            this.Align(size);

            var read = this.Read(size * knownLength);

            var result = MemoryMarshal.Cast<byte, T>(read);

            if (result.Length != knownLength)
            {
                throw new InvalidOperationException($"Read length {read.Length} doesn't match known length {knownLength}");
            }

            return result;
        }

        public ReadOnlyMemory<T> ReadConformantVaryingArray<T>()
            where T : struct
        {
            if (typeof(T) == typeof(char))
            {
                var span = MemoryMarshal.Cast<char, T>(this.ReadConformantVaryingCharArray());

                return new ReadOnlyMemory<T>(span.ToArray());
            }

            return default;
        }

        public ReadOnlySpan<char> ReadConformantVaryingCharArray()
        {
            var total = this.ReadInt32LittleEndian();
            var unused = this.ReadInt32LittleEndian();
            var used = this.ReadInt32LittleEndian();

            var chars = this.ReadFixedPrimitiveArray<char>(used);

            if (total == used && unused == 0)
            {
                return chars;
            }

            var actual = new Span<char>(new char[total]);

            chars.CopyTo(actual.Slice(unused));

            return actual;
        }

        public IEnumerable<T> ReadConformantArray<T>(int knownSize, Func<T> reader)
            where T : INdrStruct, new()
        {
            var conformance = this.ReadInt32LittleEndian();

            if (conformance != knownSize)
            {
                throw new InvalidOperationException($"Expected size {knownSize} doesn't match conformance {conformance}");
            }

            var list = new List<T>(knownSize);

            for (var i = 0; i < knownSize; i++)
            {
                list.Add(reader());
            }

            return list;
        }

        public ReadOnlyMemory<T> ReadConformantArray<T>(int knownSize)
            where T : struct
        {
            var conformance = this.ReadInt32LittleEndian();

            if (conformance != knownSize)
            {
                throw new InvalidOperationException($"Expected size {knownSize} doesn't match conformance {conformance}");
            }

            var read = this.Read(knownSize);

            var cast = MemoryMarshal.Cast<byte, T>(read);

            return cast.ToArray();
        }

        public void ReadDeferredStructArray<T>(int knownSize, Action<IEnumerable<T>> setter)
            where T : INdrStruct, new()
        {
            this.ReadDeferred(() => setter(this.ReadConformantArray(knownSize, this.ReadStruct<T>)));
        }

        public void ReadDeferredConformantArray<T>(int knownSize, Action<ReadOnlyMemory<T>> setter)
            where T : unmanaged
        {
            this.ReadDeferred(() => setter(this.ReadConformantArray<T>(knownSize)));
        }

        public void ReadConformantStruct<T>(Action<T> setter)
            where T : INdrConformantStruct, new()
        {
            this.ReadDeferred(() => setter(this.ReadStruct<T>()));
        }

        public void ReadReferentStruct(INdrStruct thing)
        {
            var referent = this.ReadInt32LittleEndian();

            if (referent == 0)
            {
                return;
            }

            this.ReadStruct(thing);
        }

        public T ReadStruct<T>()
            where T : INdrStruct, new()
        {
            var thing = new T();

            this.ReadStruct(thing);

            return thing;
        }

        public void ReadStruct<T>(T thing)
            where T : INdrStruct
        {
            using (this.deferrals.Push())
            {
                if (thing is INdrConformantStruct conformantStruct)
                {
                    conformantStruct.UnmarshalConformance(this);
                }

                thing.Unmarshal(this);
            }
        }

        public void ReadDeferredConformantVaryingArray<T>(Action<ReadOnlyMemory<T>> callback)
            where T : struct
        {
            this.ReadDeferred(() => callback(this.ReadConformantVaryingArray<T>()));
        }

        public void ReadDeferred(Action callback)
        {
            var referent = this.ReadInt32LittleEndian();

            if (referent == 0)
            {
                return;
            }

            this.deferrals.Defer(callback);
        }

        public void ReadDeferredStructUnion(INdrUnion union)
        {
            this.ReadDeferred(() => union.UnmarshalUnion(this));
        }
    }
}