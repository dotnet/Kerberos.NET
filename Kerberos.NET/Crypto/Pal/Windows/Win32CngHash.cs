// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Kerberos.NET.Crypto.BCrypt;

namespace Kerberos.NET.Crypto
{
    internal unsafe abstract class Win32CngHash : IHashAlgorithm
    {
        // According to https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider#remarks
        // _hAlgorithm should be cached and reused, as its creation is costly.

        private readonly IntPtr phAlgorithm;
        private readonly IntPtr phHash;

        public string Algorithm { get; }

        public int HashSize { get; }

        protected Win32CngHash(string algorithm, int hashSize, ReadOnlySpan<byte> secret = default)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(hashSize >= 0);

            this.Algorithm = algorithm;
            this.HashSize = hashSize;

            this.phAlgorithm = GetCachedBCryptAlgorithmProvider(algorithm);

            ref byte rSecret = ref MemoryMarshal.GetReference(secret);

            var status = BCryptCreateHash(phAlgorithm, out phHash, IntPtr.Zero, 0, ref rSecret, secret.Length, BCryptCreateHashFlags.BCRYPT_HASH_REUSABLE_FLAG);

            ThrowIfNotSuccess(status);
        }

        public void ComputeHash(ReadOnlySpan<byte> data, Span<byte> hash)
        {
            ref byte rData = ref MemoryMarshal.GetReference(data);
            ref byte rHash = ref MemoryMarshal.GetReference(hash);

            var status = BCryptHashData(phHash, ref rData, data.Length);

            ThrowIfNotSuccess(status);

            status = BCryptFinishHash(phHash, ref rHash, hash.Length);

            ThrowIfNotSuccess(status);
        }

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            var hash = new byte[HashSize];

            ComputeHash(data, hash);

            return hash;
        }

        private bool _isDisposed;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed)
            {
                return;
            }

            _isDisposed = true;

            // Note: don't dispose, as _hAlgorithm comes from a cache (see comment at the field declaration)
            
            if (phHash != IntPtr.Zero)
            {
                BCryptDestroyHash(phHash);
            }
        }

        ~Win32CngHash() => Dispose(false);
    }
}
