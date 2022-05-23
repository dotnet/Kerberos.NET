// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Buffers;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal static class CryptoPool
    {
        internal const int ClearAll = -1;

        internal static byte[] Rent(int minimumLength) => SharedRent<byte>(minimumLength);

        internal static T[] SharedRent<T>(int minimumLength)
        {
            var rentedBuffer = ArrayPool<T>.Shared.Rent(minimumLength);
            Array.Clear(rentedBuffer, 0, rentedBuffer.Length);

            return rentedBuffer;
        }


        internal static IMemoryOwner<T> Rent<T>(int minimumLength) => new CryptoMemoryOwner<T>(minimumLength);

        internal static IMemoryOwner<T> RentUnsafe<T>(int minimumLength) => new CryptoMemoryOwner<T>(minimumLength, false);

        internal static void Return<T>(T[] array, int clearSize = ClearAll)
        {
            Debug.Assert(clearSize <= array.Length);
            bool clearWholeArray = clearSize < 0;

            if (!clearWholeArray && clearSize != 0)
            {
                Array.Clear(array, 0, clearSize);
            }

            ArrayPool<T>.Shared.Return(array, clearWholeArray);
        }
    }

    internal struct CryptoMemoryOwner<T> : IMemoryOwner<T>
    {
        private readonly T[] memory;
        private readonly bool clearAll;

        public CryptoMemoryOwner(int minimumLength, bool clearAll = true)
        {
            this.memory = CryptoPool.SharedRent<T>(minimumLength);
            this.clearAll = clearAll;

            this.Memory = new Memory<T>(this.memory);
        }

        public Memory<T> Memory { get; }

        public void Dispose()
        {
            CryptoPool.Return(this.memory, this.clearAll ? -1 : 0);
        }
    }
}
