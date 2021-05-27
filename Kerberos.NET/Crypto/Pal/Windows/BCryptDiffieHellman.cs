// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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

    public class BCryptDiffieHellman : IKeyAgreement
    {
        private const int STATUS_SUCCESS = 0;

        private const string BCRYPT = "bcrypt.dll";

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

        public static BCryptDiffieHellman Import(IExchangeKey key)
        {
            return new BCryptDiffieHellman((DiffieHellmanKey)key);
        }

        protected BCryptDiffieHellman(DiffieHellmanKey importKey = null)
        {
            var status = BCryptOpenAlgorithmProvider(ref this.hAlgorithm, BCRYPT_DH_ALGORITHM, null, 0);
            ThrowIfNotNtSuccess(status);

            if (importKey != null)
            {
                this.ImportKey(importKey, ref this.hPrivateKey);
            }
            else
            {
                this.GenerateKey(this.Modulus, this.Generator, ref this.hPrivateKey);
            }

            this.PublicKey = this.ExportKey(BCRYPT_DH_PUBLIC_BLOB, importKey?.CacheExpiry);
            this.PrivateKey = this.ExportKey(BCRYPT_DH_PRIVATE_BLOB, importKey?.CacheExpiry);
        }

        private unsafe void GenerateKey(ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> generator, ref IntPtr hPrivateKey)
        {
            var status = BCryptGenerateKeyPair(this.hAlgorithm, ref hPrivateKey, this.ModulusSize, 0);
            ThrowIfNotNtSuccess(status);

            var structSize = sizeof(BCRYPT_DH_PARAMETER_HEADER) + modulus.Length + generator.Length;

            using (var rented = CryptoPool.Rent<byte>(structSize))
            {
                rented.Memory.Span.Fill(0);

                fixed (byte* pParam = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    BCRYPT_DH_PARAMETER* param = (BCRYPT_DH_PARAMETER*)pParam;

                    param->Header.CbLength = structSize;
                    param->Header.CbKeyLength = modulus.Length;
                    param->Header.DwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

                    modulus.CopyTo(rented.Memory.Slice(sizeof(BCRYPT_DH_PARAMETER_HEADER)));
                    generator.CopyTo(rented.Memory.Slice(sizeof(BCRYPT_DH_PARAMETER_HEADER) + modulus.Length));

                    status = BCryptSetProperty(hPrivateKey, BCRYPT_DH_PARAMETERS, pParam, param->Header.CbLength, 0);
                    ThrowIfNotNtSuccess(status);
                }
            }

            status = BCryptFinalizeKeyPair(hPrivateKey, 0);
            ThrowIfNotNtSuccess(status);
        }

        public int ModulusSize => this.Modulus.Length * 8;

        protected virtual ReadOnlyMemory<byte> Modulus { get; }

        protected virtual ReadOnlyMemory<byte> Generator { get; }

        protected virtual ReadOnlyMemory<byte> Factor { get; set; }

        public IExchangeKey PublicKey { get; }

        public IExchangeKey PrivateKey { get; }

        public unsafe void Dispose()
        {
            this.Dispose(true);

            GC.SuppressFinalize(this);
        }

        protected virtual unsafe void Dispose(bool disposing)
        {
            if (disposing)
            {
                // managed
            }

            int status;

            if (this.hAlgorithm != IntPtr.Zero)
            {
                status = BCryptCloseAlgorithmProvider(this.hAlgorithm, 0);
                ThrowIfNotNtSuccess(status);
            }

            if (this.hPrivateKey != IntPtr.Zero)
            {
                status = BCryptDestroyKey(this.hPrivateKey);
                ThrowIfNotNtSuccess(status);
            }

            if (this.hPublicKey != IntPtr.Zero)
            {
                status = BCryptDestroyKey(this.hPublicKey);
                ThrowIfNotNtSuccess(status);
            }

            if (this.phAgreedSecret != IntPtr.Zero)
            {
                status = BCryptDestroySecret(this.phAgreedSecret);
                ThrowIfNotNtSuccess(status);
            }
        }

        private static void ThrowIfNotNtSuccess(int status)
        {
            if (status != STATUS_SUCCESS)
            {
                throw new Win32Exception(status);
            }
        }

        private unsafe DiffieHellmanKey ExportKey(string keyType, DateTimeOffset? expiry)
        {
            int status = 0;

            status = BCryptExportKey(this.hPrivateKey, IntPtr.Zero, keyType, null, 0, out int pcbResult, 0);

            ThrowIfNotNtSuccess(status);

            DiffieHellmanKey key;

            using (var rental = CryptoPool.Rent<byte>(pcbResult))
            {
                var output = rental.Memory;

                fixed (byte* pbOutput = &MemoryMarshal.GetReference(output.Span))
                {
                    status = BCryptExportKey(this.hPrivateKey, IntPtr.Zero, keyType, pbOutput, pcbResult, out pcbResult, 0);

                    ThrowIfNotNtSuccess(status);

                    BCRYPT_DH_KEY_BLOB* param = (BCRYPT_DH_KEY_BLOB*)pbOutput;

                    key = new DiffieHellmanKey()
                    {
                        KeyLength = param->Header.CbKey,
                        Algorithm = param->Header.CbKey < 256 ? KeyAgreementAlgorithm.DiffieHellmanModp2 : KeyAgreementAlgorithm.DiffieHellmanModp14,
                        Type = param->Header.DwMagic == BCRYPT_DH_PRIVATE_MAGIC ? AsymmetricKeyType.Private : AsymmetricKeyType.Public,
                        CacheExpiry = expiry
                    };
                }

                var export = output.Span.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER));

                key.Modulus = Copy(export.Slice(0, key.KeyLength));
                key.Generator = Copy(export.Slice(key.KeyLength, key.KeyLength));
                key.PublicComponent = Copy(export.Slice(key.KeyLength + key.KeyLength, key.KeyLength));

                if (key.Type == AsymmetricKeyType.Private)
                {
                    key.PrivateComponent = Copy(export.Slice(key.KeyLength + key.KeyLength + key.KeyLength, key.KeyLength));
                }

                key.Factor = Copy(this.Factor.Span);
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
                key = (DiffieHellmanKey)this.PublicKey;

                keyType = BCRYPT_DH_PUBLIC_BLOB;
                dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
                structSize = sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + (key.KeyLength * 3);
            }

            this.Factor = incoming.Factor.ToArray();

            using (var rented = CryptoPool.Rent<byte>(structSize))
            {
                rented.Memory.Span.Fill(0);

                fixed (byte* pbInput = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    BCRYPT_DH_KEY_BLOB* param = (BCRYPT_DH_KEY_BLOB*)pbInput;

                    param->Header.DwMagic = dwMagic;
                    param->Header.CbKey = key.KeyLength;

                    key.Modulus.CopyTo(
                        rented.Memory.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER))
                    );

                    key.Generator.CopyTo(
                        rented.Memory.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + key.Modulus.Length)
                    );

                    incoming.PublicComponent.CopyTo(
                        rented.Memory.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + key.Modulus.Length + key.Generator.Length)
                    );

                    if (incoming.Type == AsymmetricKeyType.Private && incoming.PrivateComponent.Length > 0)
                    {
                        incoming.PrivateComponent.CopyTo(
                            rented.Memory.Slice(sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + key.Modulus.Length + key.Generator.Length + key.PublicComponent.Length)
                        );
                    }

                    var status = BCryptImportKeyPair(
                        this.hAlgorithm,
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

        public void ImportPartnerKey(IExchangeKey incoming)
        {
            if (!(incoming is DiffieHellmanKey key) || key is null)
            {
                throw new ArgumentNullException(nameof(incoming));
            }

            this.ImportKey(key, ref this.hPublicKey);
        }

        public unsafe ReadOnlyMemory<byte> GenerateAgreement()
        {
            if (this.hPublicKey == IntPtr.Zero)
            {
                throw new NotSupportedException("A partner key must be imported first");
            }

            int status;

            if (this.phAgreedSecret != IntPtr.Zero)
            {
                status = BCryptDestroySecret(this.phAgreedSecret);
                ThrowIfNotNtSuccess(status);
            }

            this.phAgreedSecret = IntPtr.Zero;

            status = BCryptSecretAgreement(this.hPrivateKey, this.hPublicKey, ref this.phAgreedSecret, 0);

            ThrowIfNotNtSuccess(status);

            int pcbResult = 0;

            status = BCryptDeriveKey(this.phAgreedSecret, BCRYPT_KDF_RAW_SECRET, null, null, 0, ref pcbResult, 0);

            ThrowIfNotNtSuccess(status);

            var pbDerivedKey = new Memory<byte>(new byte[pcbResult]);

            fixed (byte* pDerivedKey = &MemoryMarshal.GetReference(pbDerivedKey.Span))
            {
                status = BCryptDeriveKey(this.phAgreedSecret, BCRYPT_KDF_RAW_SECRET, null, pDerivedKey, pbDerivedKey.Length, ref pcbResult, 0);

                ThrowIfNotNtSuccess(status);
            }

            pbDerivedKey.Span.Reverse();

            return pbDerivedKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_PARAMETER
        {
            public BCRYPT_DH_PARAMETER_HEADER Header;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_PARAMETER_HEADER
        {
            public int CbLength;
            public int DwMagic;
            public int CbKeyLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_KEY_BLOB
        {
            public BCRYPT_DH_KEY_BLOB_HEADER Header;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_DH_KEY_BLOB_HEADER
        {
            public int DwMagic;
            public int CbKey;
        }

        [DllImport(BCRYPT, CharSet = CharSet.Unicode, SetLastError = true)]
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
        private static unsafe extern int BCryptSetProperty(
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

        [DllImport(BCRYPT, CharSet = CharSet.Unicode, SetLastError = true)]
        private static unsafe extern int BCryptExportKey(
           IntPtr hKey,
           IntPtr hExportKey,
           string pszBlobType,
           byte* pbOutput,
           int cbOutput,
           out int pcbResult,
           int dwFlags
        );

        [DllImport(BCRYPT, CharSet = CharSet.Unicode, SetLastError = true)]
        private static unsafe extern int BCryptImportKeyPair(
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
        private static unsafe extern int BCryptDeriveKey(
            IntPtr hSharedSecret,
            string pwszKDF,
            void* pParameterList,
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