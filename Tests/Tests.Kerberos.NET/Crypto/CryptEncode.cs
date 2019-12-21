using System;
using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Crypto
{
    public unsafe struct CERT_X942_DH_PARAMETERS
    {
        public CRYPT_UINT_BLOB p;
        public CRYPT_UINT_BLOB g;
        public CRYPT_UINT_BLOB q;
        public CRYPT_UINT_BLOB j;
        public CERT_X942_DH_VALIDATION_PARAMS* pValidationParams;
    }

    public struct CERT_X942_DH_VALIDATION_PARAMS
    {

    }

    public unsafe struct CRYPT_UINT_BLOB
    {
        public int cbData;
        public byte* pbData;
    }

    internal unsafe static class CryptEncode
    {
        internal const int X509_ASN_ENCODING = 0x00000001;
        internal const int X942_DH_PARAMETERS = 50;
        internal const int X509_DH_PUBLICKEY = 38;

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
                if (!CryptDecodeObject(X509_ASN_ENCODING, new IntPtr(X509_DH_PUBLICKEY), pData, data.Length, 0, null, ref pcbStructInfo))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                var structInfo = new Memory<byte>(new byte[pcbStructInfo]);

                fixed (byte* pStructInfo = &MemoryMarshal.GetReference(structInfo.Span))
                {
                    if (!CryptDecodeObject(X509_ASN_ENCODING, new IntPtr(X509_DH_PUBLICKEY), pData, data.Length, 0, pStructInfo, ref pcbStructInfo))
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
                    cbData = publicKey.Span.Length,
                    pbData = pPub
                };

                CRYPT_UINT_BLOB* pDhKey = &dhKey;

                if (!CryptEncodeObject(X509_ASN_ENCODING, new IntPtr(X509_DH_PUBLICKEY), pDhKey, null, ref pcbEncoded))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                using (var rented = Rent(pcbEncoded))
                {
                    fixed (byte* pbEncoded = &MemoryMarshal.GetReference(rented.Memory.Span))
                    {
                        if (!CryptEncodeObject(X509_ASN_ENCODING, new IntPtr(X509_DH_PUBLICKEY), pDhKey, pbEncoded, ref pcbEncoded))
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
                    p = new CRYPT_UINT_BLOB { cbData = publicKey.Modulus.Length, pbData = pM },
                    g = new CRYPT_UINT_BLOB { cbData = publicKey.Generator.Length, pbData = pG },
                    q = new CRYPT_UINT_BLOB { cbData = publicKey.Factor.Length, pbData = pQ },
                });
            }
        }

        private static byte[] CryptEncodeObject(CERT_X942_DH_PARAMETERS parameters)
        {
            CERT_X942_DH_PARAMETERS* pParams = &parameters;

            int pcbEncoded = 0;

            if (!CryptEncodeObject(X509_ASN_ENCODING, new IntPtr(X942_DH_PARAMETERS), pParams, null, ref pcbEncoded))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            using (var rented = Rent(pcbEncoded))
            {
                fixed (byte* pbEncoded = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    if (!CryptEncodeObject(X509_ASN_ENCODING, new IntPtr(X942_DH_PARAMETERS), pParams, pbEncoded, ref pcbEncoded))
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
