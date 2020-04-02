using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal abstract class Win32CspHash : IHashAlgorithm
    {
        // TODO gfoidl: Cache, see remarks https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider#remarks
        private readonly IntPtr _hAlgorithm;
        private readonly IntPtr _hHash;

        public string Algorithm { get; }
        public int HashSize { get; }

        protected Win32CspHash(string algorithm, int hashSize, ReadOnlySpan<byte> secret = default)
        {
            Debug.Assert(algorithm != null);
            Debug.Assert(hashSize >= 0);

            Algorithm = algorithm;
            HashSize = hashSize;

            Interop.BCryptOpenAlgorithmProvider(out _hAlgorithm, algorithm).CheckSuccess();

            ref byte rSecret = ref MemoryMarshal.GetReference(secret);
            Interop.BCryptCreateHash(_hAlgorithm, out _hHash, IntPtr.Zero, 0, ref rSecret, secret.Length, Interop.BCryptCreateHashFlags.BCRYPT_HASH_REUSABLE_FLAG).CheckSuccess();
        }

        public ReadOnlyMemory<byte> ComputeHash(byte[] data) => ComputeHash(data.AsSpan());
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> data) => ComputeHash(data.Span);

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            var hash = new byte[HashSize];

            ComputeHash(data, hash);

            return hash;
        }

        public void ComputeHash(ReadOnlySpan<byte> data, Span<byte> hash)
        {
            ref byte rData = ref MemoryMarshal.GetReference(data);
            ref byte rHash = ref MemoryMarshal.GetReference(hash);

            Interop.BCryptHashData(_hHash, ref rData, data.Length).CheckSuccess();
            Interop.BCryptFinishHash(_hHash, ref rHash, hash.Length).CheckSuccess();
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

            if (_hAlgorithm != IntPtr.Zero)
            {
                Interop.BCryptCloseAlgorithmProvider(_hAlgorithm);
            }

            if (_hHash != IntPtr.Zero)
            {
                Interop.BCryptDestroyHash(_hHash);
            }
        }

        ~Win32CspHash() => Dispose(false);
    }
}
