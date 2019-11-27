using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public abstract class BCryptDiffieHellman : IKeyAgreement
    {
        private const int STATUS_SUCCESS = 0;

        private const string BCRYPT_DH_ALGORITHM = "DH";
        private const string BCRYPT_DH_PARAMETERS = "DHParameters";

        private const string BCRYPT_DH_PUBLIC_BLOB = "DHPUBLICBLOB";
        private const string BCRYPT_KDF_RAW_SECRET = "TRUNCATE";

        protected const int BCRYPT_DH_PARAMETERS_MAGIC = 0x4d504844;

        private readonly IntPtr hAlgorithm;
        private readonly IntPtr hPrivateKey;

        private IntPtr hPublicKey;
        private IntPtr phAgreedSecret;

        internal unsafe BCryptDiffieHellman()
        {
            var structSize = sizeof(BCRYPT_DH_PARAMETER_HEADER) + Modulus.Length + Generator.Length;

            using (var rented = CryptoPool.Rent<byte>(structSize))
            {
                rented.Memory.Span.Fill(0);

                fixed (byte* pParam = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    BCRYPT_DH_PARAMETER* param = (BCRYPT_DH_PARAMETER*)pParam;

                    param->header.cbLength = structSize;
                    param->header.cbKeyLength = Modulus.Length;
                    param->header.dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

                    Modulus.CopyTo(rented.Memory.Slice(sizeof(BCRYPT_DH_PARAMETER_HEADER)));
                    Generator.CopyTo(rented.Memory.Slice(sizeof(BCRYPT_DH_PARAMETER_HEADER) + Modulus.Length));

                    var status = BCryptOpenAlgorithmProvider(ref hAlgorithm, BCRYPT_DH_ALGORITHM, null, 0);
                    ThrowIfNotNtSuccess(status);

                    status = BCryptGenerateKeyPair(hAlgorithm, ref hPrivateKey, ModulusSize, 0);
                    ThrowIfNotNtSuccess(status);

                    status = BCryptSetProperty(hPrivateKey, BCRYPT_DH_PARAMETERS, pParam, param->header.cbLength, 0);
                    ThrowIfNotNtSuccess(status);

                    status = BCryptFinalizeKeyPair(hPrivateKey, 0);
                    ThrowIfNotNtSuccess(status);
                }
            }

            // TODO: this probably isn't the correct final format as it moves across the wire

            PublicKey = ExportKey(BCRYPT_DH_PUBLIC_BLOB);
        }

        public int ModulusSize => Modulus.Length * 8;

        public abstract byte[] Modulus { get; }

        public abstract byte[] Generator { get; }

        public ReadOnlyMemory<byte> PublicKey { get; }

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

        private unsafe ReadOnlyMemory<byte> ExportKey(string keyType)
        {
            int status = 0;

            status = BCryptExportKey(hPrivateKey, IntPtr.Zero, keyType, null, 0, out int pcbResult, 0);

            ThrowIfNotNtSuccess(status);

            var output = new Memory<byte>(new byte[pcbResult]);

            fixed (byte* pbOutput = &MemoryMarshal.GetReference(output.Span))
            {
                status = BCryptExportKey(hPrivateKey, IntPtr.Zero, keyType, pbOutput, pcbResult, out pcbResult, 0);

                ThrowIfNotNtSuccess(status);
            }

            return output;
        }

        public unsafe void ImportPartnerKey(ReadOnlySpan<byte> publicKey)
        {
            using (var rented = CryptoPool.Rent<byte>(publicKey.Length))
            {
                publicKey.CopyTo(rented.Memory.Span);

                fixed (byte* pbInput = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    var status = BCryptImportKeyPair(hAlgorithm, IntPtr.Zero, BCRYPT_DH_PUBLIC_BLOB, ref hPublicKey, pbInput, publicKey.Length, 0);

                    ThrowIfNotNtSuccess(status);
                }
            }
        }

        public unsafe ReadOnlyMemory<byte> GenerateAgreement()
        {
            if (hPublicKey == IntPtr.Zero)
            {
                throw new NotSupportedException("A partner key must be imported first");
            }

            phAgreedSecret = IntPtr.Zero;

            var status = BCryptSecretAgreement(hPrivateKey, hPublicKey, ref phAgreedSecret, 0);

            ThrowIfNotNtSuccess(status);

            int cbDerivedKey = 0;
            int pcbResult = 0;

            IntPtr pParameterList = IntPtr.Zero;

            status = BCryptDeriveKey(phAgreedSecret, BCRYPT_KDF_RAW_SECRET, ref pParameterList, null, ref cbDerivedKey, ref pcbResult, 0);

            ThrowIfNotNtSuccess(status);

            var pbDerivedKey = new Memory<byte>(new byte[pcbResult]);

            fixed (byte* pDerivedKey = &MemoryMarshal.GetReference(pbDerivedKey.Span))
            {
                status = BCryptDeriveKey(phAgreedSecret, BCRYPT_KDF_RAW_SECRET, ref pParameterList, pDerivedKey, ref cbDerivedKey, ref pcbResult, 0);

                ThrowIfNotNtSuccess(status);
            }

            return pbDerivedKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct BCRYPT_DH_PARAMETER
        {
            public BCRYPT_DH_PARAMETER_HEADER header;

            public byte* prime;

            public byte* generator;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_PARAMETER_HEADER
        {
            public int cbLength;
            public int dwMagic;
            public int cbKeyLength;
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
            ref IntPtr pParameterList,
            byte* pbDerivedKey,
            ref int cbDerivedKey,
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
