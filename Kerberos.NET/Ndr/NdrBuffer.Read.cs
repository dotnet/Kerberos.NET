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
            backingBuffer = MemoryMarshal.AsMemory(memory);

            MoveByOffset(0);
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

            if (header.ObjectBufferLength > BytesAvailable)
            {
                throw new InvalidDataException($"Expected length ({header.ObjectBufferLength} bytes) is greater than available bytes ({BytesAvailable} bytes)");
            }

            ReadReferentStruct(thing);
        }

        public void ReadDeferredArray(int knownSize, Action op)
        {
            for (var i = 0; i < knownSize; i++)
            {
                ReadDeferred(op);
            }
        }

        public ReadOnlyMemory<byte> ReadMemory(int length) => MoveByOffset(length).Slice(0, length);

        public ReadOnlySpan<byte> Read(int length) => ReadMemory(length).Span;

        public byte ReadByteLittleEndian() => MoveByOffset(1).Span[0];

        public short ReadInt16LittleEndian()
        {
            return BinaryPrimitives.ReadInt16LittleEndian(MoveByPrimitiveTypeSize<short>());
        }

        public int ReadInt32LittleEndian()
        {
            return BinaryPrimitives.ReadInt32LittleEndian(MoveByPrimitiveTypeSize<int>());
        }

        public uint ReadUInt32LittleEndian()
        {
            return BinaryPrimitives.ReadUInt32LittleEndian(MoveByPrimitiveTypeSize<uint>());
        }

        public long ReadInt64LittleEndian()
        {
            return BinaryPrimitives.ReadInt64LittleEndian(MoveByPrimitiveTypeSize<long>());
        }

        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        public ReadOnlySpan<T> ReadFixedPrimitiveArray<T>(int knownLength) where T : struct
        {
            if (knownLength == 0)
            {
                return ReadOnlySpan<T>.Empty;
            }

            int size = SizeOf<T>();

            Align(size);

            var read = Read(size * knownLength);

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
                var span = MemoryMarshal.Cast<char, T>(ReadConformantVaryingCharArray());

                return new ReadOnlyMemory<T>(span.ToArray());
            }

            return default;
        }

        public ReadOnlySpan<char> ReadConformantVaryingCharArray()
        {
            var total = ReadInt32LittleEndian();

            var unused = ReadInt32LittleEndian();
            var used = ReadInt32LittleEndian();

            var chars = ReadFixedPrimitiveArray<char>(used);

            if (chars.Length > 0 && chars[chars.Length - 1] == '\0')
            {
                chars = chars.Slice(0, chars.Length - 1);
            }

            if (total == used && unused == 0)
            {
                return chars;
            }

            return chars.Slice(unused, used);
        }

        public IEnumerable<T> ReadConformantArray<T>(int knownSize, Func<T> reader)
            where T : INdrStruct, new()
        {
            var conformance = ReadInt32LittleEndian();

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
            var conformance = ReadInt32LittleEndian();

            if (conformance != knownSize)
            {
                throw new InvalidOperationException($"Expected size {knownSize} doesn't match conformance {conformance}");
            }

            var read = Read(knownSize);

            var cast = MemoryMarshal.Cast<byte, T>(read);

            return cast.ToArray();
        }

        public void ReadDeferredStructArray<T>(int knownSize, Action<IEnumerable<T>> setter)
            where T : INdrStruct, new()
        {
            ReadDeferred(() => setter(ReadConformantArray(knownSize, ReadStruct<T>)));
        }

        public void ReadDeferredConformantArray<T>(int knownSize, Action<ReadOnlyMemory<T>> setter)
            where T : unmanaged
        {
            ReadDeferred(() => setter(ReadConformantArray<T>(knownSize)));
        }

        public void ReadDeferredStruct<T>(Action<T> setter)
            where T : INdrStruct, new()
        {
            ReadDeferred(() => setter(ReadReferentStruct<T>()));
        }

        public void ReadReferentStruct(INdrStruct thing)
        {
            var referent = ReadInt32LittleEndian();

            if (referent == 0)
            {
                return;
            }

            ReadStruct(thing);
        }

        public T ReadReferentStruct<T>()
            where T : INdrStruct, new()
        {
            var thing = new T();

            ReadReferentStruct(thing);

            return thing;
        }

        public T ReadStruct<T>()
            where T : INdrStruct, new()
        {
            var thing = new T();

            ReadStruct(thing);

            return thing;
        }

        public void ReadStruct<T>(T thing)
            where T : INdrStruct
        {
            using (deferrals.Push())
            {
                thing.Unmarshal(this);
            }
        }

        public void ReadDeferredConformantVaryingArray<T>(Action<ReadOnlyMemory<T>> callback)
            where T : struct
        {
            ReadDeferred(() => callback(ReadConformantVaryingArray<T>()));
        }

        public void ReadDeferred(Action callback)
        {
            var referent = ReadInt32LittleEndian();

            if (referent == 0)
            {
                return;
            }

            deferrals.Defer(callback);
        }

        public void ReadDeferredStructUnion(INdrUnion union)
        {
            ReadDeferred(() => union.UnmarshalUnion(this));
        }
    }
}
