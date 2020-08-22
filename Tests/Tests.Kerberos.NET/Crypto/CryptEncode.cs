// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
{
    internal unsafe struct CERT_X942_DH_PARAMETERS : IEquatable<CERT_X942_DH_PARAMETERS>
    {
        public CRYPT_UINT_BLOB P;
        public CRYPT_UINT_BLOB G;
        public CRYPT_UINT_BLOB Q;
        public CRYPT_UINT_BLOB J;
        public CERT_X942_DH_VALIDATION_PARAMS* PValidationParams;

        public override bool Equals(object obj)
        {
            return false;
        }

        public override int GetHashCode()
        {
            return 0;
        }

        public static bool operator ==(CERT_X942_DH_PARAMETERS left, CERT_X942_DH_PARAMETERS right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(CERT_X942_DH_PARAMETERS left, CERT_X942_DH_PARAMETERS right)
        {
            return !(left == right);
        }

        public bool Equals(CERT_X942_DH_PARAMETERS other)
        {
            return false;
        }
    }

    internal struct CERT_X942_DH_VALIDATION_PARAMS
    {
    }

    internal unsafe struct CRYPT_UINT_BLOB
    {
        public int CbData;
        public byte* PbData;
    }

    internal static unsafe class CryptEncode
    {
        internal const int X509AsnEncoding = 0x00000001;
        internal const int X942DhParameters = 50;
        internal const int X509DhPublicKey = 38;

        private static Span<byte> Reverse(ReadOnlySpan<byte> data)
        {
            var copy = new Span<byte>(new byte[data.Length]);

            data.CopyTo(copy);

            copy.Reverse();

            return copy;
        }

        public static ReadOnlyMemory<byte> CryptDecodePublicParameter(ReadOnlyMemory<byte> data)
        {
            int pcbStructInfo = 0;

            fixed (byte* pData = &MemoryMarshal.GetReference(data.Span))
            {
                if (!CryptDecodeObject(X509AsnEncoding, new IntPtr(X509DhPublicKey), pData, data.Length, 0, null, ref pcbStructInfo))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var structInfo = new Memory<byte>(new byte[pcbStructInfo]);

                fixed (byte* pStructInfo = &MemoryMarshal.GetReference(structInfo.Span))
                {
                    if (!CryptDecodeObject(X509AsnEncoding, new IntPtr(X509DhPublicKey), pData, data.Length, 0, pStructInfo, ref pcbStructInfo))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }

                return structInfo;
            }
        }

        public static ReadOnlyMemory<byte> CryptEncodeObject(ReadOnlyMemory<byte> publicKey)
        {
            int pcbEncoded = 0;

            fixed (byte* pPub = &MemoryMarshal.GetReference(publicKey.Span))
            {
                var dhKey = new CRYPT_UINT_BLOB
                {
                    CbData = publicKey.Span.Length,
                    PbData = pPub
                };

                CRYPT_UINT_BLOB* pDhKey = &dhKey;

                if (!CryptEncodeObject(X509AsnEncoding, new IntPtr(X509DhPublicKey), pDhKey, null, ref pcbEncoded))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                using (var rented = Rent(pcbEncoded))
                {
                    fixed (byte* pbEncoded = &MemoryMarshal.GetReference(rented.Memory.Span))
                    {
                        if (!CryptEncodeObject(X509AsnEncoding, new IntPtr(X509DhPublicKey), pDhKey, pbEncoded, ref pcbEncoded))
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    }

                    return rented.Memory.Slice(0, pcbEncoded).ToArray();
                }
            }
        }

        internal static byte[] CryptEncodeObject(DiffieHellmanKey publicKey)
        {
            fixed (byte* pM = &MemoryMarshal.GetReference(Reverse(publicKey.Modulus.Span)))
            fixed (byte* pG = &MemoryMarshal.GetReference(Reverse(publicKey.Generator.Span)))
            fixed (byte* pQ = &MemoryMarshal.GetReference(Reverse(publicKey.Factor.Span)))
            {
                return CryptEncodeObject(new CERT_X942_DH_PARAMETERS
                {
                    P = new CRYPT_UINT_BLOB { CbData = publicKey.Modulus.Length, PbData = pM },
                    G = new CRYPT_UINT_BLOB { CbData = publicKey.Generator.Length, PbData = pG },
                    Q = new CRYPT_UINT_BLOB { CbData = publicKey.Factor.Length, PbData = pQ },
                });
            }
        }

        private static byte[] CryptEncodeObject(CERT_X942_DH_PARAMETERS parameters)
        {
            CERT_X942_DH_PARAMETERS* pParams = &parameters;

            int pcbEncoded = 0;

            if (!CryptEncodeObject(X509AsnEncoding, new IntPtr(X942DhParameters), pParams, null, ref pcbEncoded))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            using (var rented = Rent(pcbEncoded))
            {
                fixed (byte* pbEncoded = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    if (!CryptEncodeObject(X509AsnEncoding, new IntPtr(X942DhParameters), pParams, pbEncoded, ref pcbEncoded))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }

                return rented.Memory.Slice(0, pcbEncoded).ToArray();
            }
        }

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptEncodeObject(int dwCertEncodingType, IntPtr lpszStructType, void* pvStructInfo, byte* pbEncoded, ref int pcbEncoded);

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptDecodeObject(int dwCertEncodingType, IntPtr lpszStructType, byte* pbEncoded, int cbEncoded, int dwFlags, void* pvStructInfo, ref int pcbStructInfo);

        private static IMemoryOwner<byte> Rent(int len)
        {
            return MemoryPool<byte>.Shared.Rent(len);
        }
    }
}