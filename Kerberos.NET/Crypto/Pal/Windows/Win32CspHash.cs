using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto.Pal.Windows
{
    internal unsafe abstract class Win32CspHash : IHashAlgorithm
    {
        private readonly IntPtr _hProvider;
        private readonly IntPtr _hHash;

        public string Algorithm { get; }
        public int CAlg { get; }
        public int HashSize { get; }

        protected Win32CspHash(string algorithm, int calg, int hashSize)
        {
            Algorithm = algorithm;
            CAlg = calg;
            HashSize = hashSize;

            if (!Interop.CryptAcquireContext(ref _hProvider, Algorithm, null, (int)Interop.ProviderType.PROV_RSA_AES, (uint)Interop.CryptAcquireContextFlags.None)
             && !Interop.CryptAcquireContext(ref _hProvider, Algorithm, null, (int)Interop.ProviderType.PROV_RSA_AES, (uint)Interop.CryptAcquireContextFlags.CRYPT_NEWKEYSET))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!Interop.CryptCreateHash(_hProvider, CAlg, IntPtr.Zero, 0, ref _hHash))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public ReadOnlyMemory<byte> ComputeHash(byte[] data) => ComputeHash(data.AsSpan());
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> data) => ComputeHash(data.Span);

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            byte[] hash = new byte[HashSize];

            ComputeHash(data, hash, out int bytesWritten);
            Debug.Assert(bytesWritten == hash.Length);

            return hash;
        }

        public void ComputeHash(ReadOnlySpan<byte> data, Span<byte> hash, out int bytesWritten)
        {
            CheckDisposed();

            fixed (byte* pData = data)
            {
                if (!Interop.CryptHashData(_hHash, pData, data.Length, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }

            Debug.Assert(hash.Length >= HashSize);
            int hashSize = HashSize;

            fixed (byte* pHash = &MemoryMarshal.GetReference(hash))
            {
                if (!Interop.CryptGetHashParam(_hHash, Interop.HP_HASHVAL, pHash, ref hashSize, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                bytesWritten = hashSize;
            }
        }

        private bool _isDisposed;

        private void CheckDisposed() => Debug.Assert(!_isDisposed);

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~Win32CspHash() => Dispose(false);

        protected void Dispose(bool disposing)
        {
            if (_isDisposed) return;

            _isDisposed = true;

            if (_hHash != IntPtr.Zero)
            {
                Interop.CryptDestroyHash(_hHash);
            }

            if (_hProvider != IntPtr.Zero)
            {
                Interop.CryptReleaseContext(_hProvider, 0);
            }
        }
    }
}
