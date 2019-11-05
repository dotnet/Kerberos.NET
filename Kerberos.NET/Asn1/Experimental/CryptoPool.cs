// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal static class CryptoPool
    {
        internal const int ClearAll = -1;

        internal static byte[] Rent(int minimumLength) => SharedRent<byte>(minimumLength);

        internal static T[] SharedRent<T>(int minimumLength) => ArrayPool<T>.Shared.Rent(minimumLength);

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
            memory = CryptoPool.SharedRent<T>(minimumLength);
            this.clearAll = clearAll;

            Memory = new Memory<T>(memory);
        }

        public Memory<T> Memory { get; }

        public void Dispose()
        {
            CryptoPool.Return(memory, clearAll ? -1 : 0);
        }
    }
}
