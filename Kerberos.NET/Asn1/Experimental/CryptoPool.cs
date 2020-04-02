// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

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
            if (array == null)
            {
                return;
            }

            Debug.Assert(clearSize <= array.Length);
            bool clearWholeArray = clearSize < 0;

            if (!clearWholeArray && clearSize != 0)
            {
                ZeroMemory(array.AsSpan(0, clearSize));
            }

            ArrayPool<T>.Shared.Return(array, clearWholeArray);
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static void ZeroMemory<T>(Span<T> buffer)
        {
            // NoOptimize to prevent the optimizer from deciding this call is unnecessary
            // NoInlining to prevent the inliner from forgetting that the method was no-optimize
            buffer.Clear();
        }
    }

    internal struct CryptoMemoryOwner<T> : IMemoryOwner<T>
    {
        private readonly T[] _memory;
        private readonly bool _clearAll;

        public CryptoMemoryOwner(int minimumLength, bool clearAll = true)
        {
            _memory = CryptoPool.SharedRent<T>(minimumLength);
            _clearAll = clearAll;

            Memory = _memory.AsMemory();
        }

        public Memory<T> Memory { get; }

        public void Dispose()
        {
            CryptoPool.Return(_memory, _clearAll ? -1 : 0);
        }
    }
}
