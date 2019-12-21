using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public enum AsymmetricKeyType
    {
        Public,
        Private
    }

    public class DiffieHellmanKey
    {
        public AsymmetricKeyType Type { get; set; }

        public int KeyLength { get; set; }

        public ReadOnlyMemory<byte> Modulus { get; set; }

        public ReadOnlyMemory<byte> Generator { get; set; }

        public ReadOnlyMemory<byte> Factor { get; set; }

        public ReadOnlyMemory<byte> Public { get; set; }

        public ReadOnlyMemory<byte> Private { get; set; }
    }

    public class BCryptDiffieHellman : IKeyAgreement
    {
        private const int STATUS_SUCCESS = 0;

        private const string BCRYPT_DH_ALGORITHM = "DH";
        private const string BCRYPT_DH_PARAMETERS = "DHParameters";

        private const string BCRYPT_DH_PRIVATE_BLOB = "DHPRIVATEBLOB";
        private const string BCRYPT_DH_PUBLIC_BLOB = "DHPUBLICBLOB";
        private const string BCRYPT_KDF_RAW_SECRET = "TRUNCATE";

        private const int BCRYPT_DH_PARAMETERS_MAGIC = 0x4d504844;
        private const int BCRYPT_DH_PUBLIC_MAGIC = 0x42504844;
        private const int BCRYPT_DH_PRIVATE_MAGIC = 0x56504844;

        private readonly IntPtr hAlgorithm;
        private readonly IntPtr hPrivateKey;

        private IntPtr hPublicKey;
        private IntPtr phAgreedSecret;

        public static BCryptDiffieHellman Import(DiffieHellmanKey key)
        {
            return new BCryptDiffieHellman(key);
        }

        protected BCryptDiffieHellman(DiffieHellmanKey importKey = null)
        {
            var status = BCryptOpenAlgorithmProvider(ref hAlgorithm, BCRYPT_DH_ALGORITHM, null, 0);
            ThrowIfNotNtSuccess(status);

            if (importKey != null)
            {
                ImportKey(importKey, ref hPrivateKey);
            }
            else
            {
                GenerateKey(Modulus, Generator, ref hPrivateKey);
            }

            PublicKey = ExportKey(BCRYPT_DH_PUBLIC_BLOB);
            PrivateKey = ExportKey(BCRYPT_DH_PRIVATE_BLOB);
        }

        private unsafe void GenerateKey(ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> generator, ref IntPtr hPrivateKey)
        {
            var status = BCryptGenerateKeyPair(hAlgorithm, ref hPrivateKey, ModulusSize, 0);
            ThrowIfNotNtSuccess(status);

            var structSize = sizeof(BCRYPT_DH_PARAMETER_HEADER) + modulus.Length + generator.Length;

            using (var rented = CryptoPool.Rent<byte>(structSize))
            {
                rented.Memory.Span.Fill(0);

                fixed (byte* pParam = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    BCRYPT_DH_PARAMETER* param = (BCRYPT_DH_PARAMETER*)pParam;

                    param->header.cbLength = structSize;
                    param->header.cbKeyLength = modulus.Length;
                    param->header.dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

                    modulus.CopyTo(rented.Memory.Slice(sizeof(BCRYPT_DH_PARAMETER_HEADER)));
                    generator.CopyTo(rented.Memory.Slice(sizeof(BCRYPT_DH_PARAMETER_HEADER) + modulus.Length));

                    status = BCryptSetProperty(hPrivateKey, BCRYPT_DH_PARAMETERS, pParam, param->header.cbLength, 0);
                    ThrowIfNotNtSuccess(status);
                }
            }

            status = BCryptFinalizeKeyPair(hPrivateKey, 0);
            ThrowIfNotNtSuccess(status);
        }

        public int ModulusSize => Modulus.Length * 8;

        protected virtual byte[] Modulus { get; }

        protected virtual byte[] Generator { get; }

        protected virtual byte[] Factor { get; set; }

        public DiffieHellmanKey PublicKey { get; }

        public DiffieHellmanKey PrivateKey { get; }

        public unsafe void Dispose()
        {
            if (hAlgorithm != IntPtr.Zero)
            {
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            }

            if (hPrivateKey != IntPtr.Zero)
            {
                BCryptDestroyKey(hPrivateKey);
            }

            if (hPublicKey != IntPtr.Zero)
            {
                BCryptDestroyKey(hPublicKey);
            }

            if (phAgreedSecret != IntPtr.Zero)
            {
                BCryptDestroySecret(phAgreedSecret);
            }
        }

        private static void ThrowIfNotNtSuccess(int status)
        {
            if (status != STATUS_SUCCESS)
            {
                throw new Win32Exception(status);
            }
        }

        private unsafe DiffieHellmanKey ExportKey(string keyType)
        {
            int status = 0;

            status = BCryptExportKey(hPrivateKey, IntPtr.Zero, keyType, null, 0, out int pcbResult, 0);

            ThrowIfNotNtSuccess(status);

            DiffieHellmanKey key;

            using (var rental = CryptoPool.Rent<byte>(pcbResult))
            {
                var output = rental.Memory;

                fixed (byte* pbOutput = &MemoryMarshal.GetReference(output.Span))
                {
                    status = BCryptExportKey(hPrivateKey, IntPtr.Zero, keyType, pbOutput, pcbResult, out pcbResult, 0);

                    ThrowIfNotNtSuccess(status);

                    BCRYPT_DH_KEY_BLOB* param = (BCRYPT_DH_KEY_BLOB*)pbOutput;

                    key = new DiffieHellmanKey()
                    {
                        KeyLength = param->header.cbKey,
                        Type = param->header.dwMagic == BCRYPT_DH_PRIVATE_MAGIC ? AsymmetricKeyType.Private : AsymmetricKeyType.Public
                    };
                }

                var export = output.Span.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER));

                key.Modulus = Copy(export.Slice(0, key.KeyLength));
                key.Generator = Copy(export.Slice(key.KeyLength, key.KeyLength));
                key.Public = Copy(export.Slice(key.KeyLength + key.KeyLength, key.KeyLength));

                if (key.Type == AsymmetricKeyType.Private)
                {
                    key.Private = Copy(export.Slice(key.KeyLength + key.KeyLength + key.KeyLength, key.KeyLength));
                }

                key.Factor = Copy(Factor);
            }

            return key;
        }

        protected static ReadOnlyMemory<byte> Copy(ReadOnlySpan<byte> data)
        {
            var copy = new byte[data.Length];

            data.CopyTo(copy);

            return copy;
        }

        private unsafe void ImportKey(DiffieHellmanKey incoming, ref IntPtr hKey)
        {
            DiffieHellmanKey key;

            string keyType;
            int dwMagic;
            int structSize;

            if (incoming.Type == AsymmetricKeyType.Private)
            {
                key = incoming;

                keyType = BCRYPT_DH_PRIVATE_BLOB;
                dwMagic = BCRYPT_DH_PRIVATE_MAGIC;
                structSize = sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + (key.KeyLength * 4);
            }
            else
            {
                key = PublicKey;

                keyType = BCRYPT_DH_PUBLIC_BLOB;
                dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
                structSize = sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + (key.KeyLength * 3);
            }

            Factor = incoming.Factor.ToArray();

            using (var rented = CryptoPool.Rent<byte>(structSize))
            {
                rented.Memory.Span.Fill(0);

                fixed (byte* pbInput = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    BCRYPT_DH_KEY_BLOB* param = (BCRYPT_DH_KEY_BLOB*)pbInput;

                    param->header.dwMagic = dwMagic;
                    param->header.cbKey = key.KeyLength;

                    key.Modulus.CopyTo(
                        rented.Memory.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER))
                    );

                    key.Generator.CopyTo(
                        rented.Memory.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + key.Modulus.Length)
                    );

                    incoming.Public.CopyTo(
                        rented.Memory.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + key.Modulus.Length + key.Generator.Length)
                    );

                    if (incoming.Type == AsymmetricKeyType.Private && incoming.Private.Length > 0)
                    {
                        incoming.Private.CopyTo(
                            rented.Memory.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + key.Modulus.Length + key.Generator.Length + key.Public.Length)
                        );
                    }

                    var status = BCryptImportKeyPair(
                        hAlgorithm,
                        IntPtr.Zero,
                        keyType,
                        ref hKey,
                        pbInput,
                        structSize,
                        0
                    );

                    ThrowIfNotNtSuccess(status);
                }
            }
        }

        public void ImportPartnerKey(DiffieHellmanKey incoming)
        {
            ImportKey(incoming, ref hPublicKey);
        }

        public unsafe ReadOnlyMemory<byte> GenerateAgreement()
        {
            if (hPublicKey == IntPtr.Zero)
            {
                throw new NotSupportedException("A partner key must be imported first");
            }

            if (phAgreedSecret != IntPtr.Zero)
            {
                BCryptDestroySecret(phAgreedSecret);
            }

            phAgreedSecret = IntPtr.Zero;

            var status = BCryptSecretAgreement(hPrivateKey, hPublicKey, ref phAgreedSecret, 0);

            ThrowIfNotNtSuccess(status);

            int pcbResult = 0;

            status = BCryptDeriveKey(phAgreedSecret, BCRYPT_KDF_RAW_SECRET, null, null, 0, ref pcbResult, 0);

            ThrowIfNotNtSuccess(status);

            var pbDerivedKey = new Memory<byte>(new byte[pcbResult]);

            fixed (byte* pDerivedKey = &MemoryMarshal.GetReference(pbDerivedKey.Span))
            {
                status = BCryptDeriveKey(phAgreedSecret, BCRYPT_KDF_RAW_SECRET, null, pDerivedKey, pbDerivedKey.Length, ref pcbResult, 0);

                ThrowIfNotNtSuccess(status);
            }

            pbDerivedKey.Span.Reverse();

            return pbDerivedKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_PARAMETER
        {
            public BCRYPT_DH_PARAMETER_HEADER header;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_PARAMETER_HEADER
        {
            public int cbLength;
            public int dwMagic;
            public int cbKeyLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_KEY_BLOB
        {
            public BCRYPT_DH_KEY_BLOB_HEADER header;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_KEY_BLOB_HEADER
        {
            public int dwMagic;
            public int cbKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCryptBuffer
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCryptBufferDesc
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers;
        }

        private const string BCRYPT = "bcrypt.dll";

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int BCryptOpenAlgorithmProvider(
            ref IntPtr hAlgorithm,
            string pszAlgId,
            string pszImplementation,
            int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int BCryptCloseAlgorithmProvider(
            IntPtr hAlgorithm,
            int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int BCryptGenerateKeyPair(
            IntPtr hAlgorithm,
            ref IntPtr hKey,
            int dwLength,
            int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Unicode, SetLastError = true)]
        private unsafe static extern int BCryptSetProperty(
            IntPtr hKey,
            string pszProperty,
            byte* pbInput,
            int cbInput,
            int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int BCryptFinalizeKeyPair(
            IntPtr hKey,
            int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private unsafe static extern int BCryptExportKey(
           IntPtr hKey,
           IntPtr hExportKey,
           string pszBlobType,
           byte* pbOutput,
           int cbOutput,
           out int pcbResult,
           int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private unsafe static extern int BCryptImportKeyPair(
           IntPtr hAlgorithm,
           IntPtr hImportKey,
           string pszBlobType,
           ref IntPtr phKey,
           byte* pbInput,
           int cbInput,
           int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int BCryptSecretAgreement(
            IntPtr hPrivKey,
            IntPtr hPubKey,
            ref IntPtr phAgreedSecret,
            int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Unicode, SetLastError = true)]
        private unsafe static extern int BCryptDeriveKey(
            IntPtr hSharedSecret,
            string pwszKDF,
            BCryptBufferDesc* pParameterList,
            byte* pbDerivedKey,
            int cbDerivedKey,
            ref int pcbResult,
            int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int BCryptDestroyKey(
            IntPtr hKey
        );

        [DllImport(BCRYPT, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int BCryptDestroySecret(
            IntPtr hSecret
        );
    }
}
