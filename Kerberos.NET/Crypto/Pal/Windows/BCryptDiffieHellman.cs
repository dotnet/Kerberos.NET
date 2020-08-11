using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Kerberos.NET.Crypto.Pal.Windows;
using static Kerberos.NET.Crypto.Pal.Windows.Interop;

namespace Kerberos.NET.Crypto
{
    public enum AsymmetricKeyType
    {
        Public,
        Private
    }

    public class BCryptDiffieHellman : IKeyAgreement
    {
        private const string BCRYPT_DH_PARAMETERS = "DHParameters";

        private const string BCRYPT_DH_PRIVATE_BLOB = "DHPRIVATEBLOB";
        private const string BCRYPT_DH_PUBLIC_BLOB = "DHPUBLICBLOB";
        private const string BCRYPT_KDF_RAW_SECRET = "TRUNCATE";

        private const int BCRYPT_DH_PARAMETERS_MAGIC = 0x4d504844;
        private const int BCRYPT_DH_PUBLIC_MAGIC = 0x42504844;
        private const int BCRYPT_DH_PRIVATE_MAGIC = 0x56504844;

        // According to https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider#remarks
        // _hAlgorithm should be cached and reused, as its creation is costly.
        private readonly IntPtr _hAlgorithm;
        private readonly IntPtr _hPrivateKey;

        private IntPtr _hPublicKey;
        private IntPtr _phAgreedSecret;

        public static BCryptDiffieHellman Import(IExchangeKey key)
        {
            return new BCryptDiffieHellman((DiffieHellmanKey)key);
        }

        protected BCryptDiffieHellman(DiffieHellmanKey importKey = null)
        {
            _hAlgorithm = BCryptAlgorithmProviderCache.GetCachedBCrypptAlgorithmProvider(CngAlgorithms.DH);

            if (importKey != null)
            {
                ImportKey(importKey, ref _hPrivateKey);
            }
            else
            {
                GenerateKey(Modulus, Generator, ref _hPrivateKey);
            }

            PublicKey = ExportKey(BCRYPT_DH_PUBLIC_BLOB, importKey?.CacheExpiry);
            PrivateKey = ExportKey(BCRYPT_DH_PRIVATE_BLOB, importKey?.CacheExpiry);
        }

        private unsafe void GenerateKey(ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> generator, ref IntPtr hPrivateKey)
        {
            BCryptGenerateKeyPair(_hAlgorithm, ref hPrivateKey, ModulusSize).CheckSuccess();

            var structSize = sizeof(BCRYPT_DH_PARAMETER_HEADER) + modulus.Length + generator.Length;

            using (IMemoryOwner<byte> rented = CryptoPool.Rent<byte>(structSize))
            {
                rented.Memory.Span.Clear();

                fixed (byte* pParam = &MemoryMarshal.GetReference(rented.Memory.Span))
                {
                    BCRYPT_DH_PARAMETER* param = (BCRYPT_DH_PARAMETER*)pParam;

                    param->header.cbLength = structSize;
                    param->header.cbKeyLength = modulus.Length;
                    param->header.dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

                    modulus.CopyTo(rented.Memory.Slice(sizeof(BCRYPT_DH_PARAMETER_HEADER)));
                    generator.CopyTo(rented.Memory.Slice(sizeof(BCRYPT_DH_PARAMETER_HEADER) + modulus.Length));

                    BCryptSetProperty(hPrivateKey, BCRYPT_DH_PARAMETERS, pParam, param->header.cbLength).CheckSuccess();
                }
            }

            BCryptFinalizeKeyPair(hPrivateKey);
        }

        public int ModulusSize => Modulus.Length * 8;

        protected virtual ReadOnlyMemory<byte> Modulus { get; }

        protected virtual ReadOnlyMemory<byte> Generator { get; }

        protected virtual ReadOnlyMemory<byte> Factor { get; set; }

        public IExchangeKey PublicKey { get; }

        public IExchangeKey PrivateKey { get; }

        private unsafe DiffieHellmanKey ExportKey(string keyType, DateTimeOffset? expiry)
        {
            BCryptExportKey(_hPrivateKey, IntPtr.Zero, keyType, null, 0, out int pcbResult).CheckSuccess();

            DiffieHellmanKey key;

            using (var rental = CryptoPool.Rent<byte>(pcbResult))
            {
                var output = rental.Memory;

                fixed (byte* pbOutput = &MemoryMarshal.GetReference(output.Span))
                {
                    BCryptExportKey(_hPrivateKey, IntPtr.Zero, keyType, pbOutput, pcbResult, out pcbResult).CheckSuccess();

                    BCRYPT_DH_KEY_BLOB* param = (BCRYPT_DH_KEY_BLOB*)pbOutput;

                    key = new DiffieHellmanKey()
                    {
                        KeyLength = param->header.cbKey,
                        Algorithm = param->header.cbKey < 256 ? KeyAgreementAlgorithm.DiffieHellmanModp2 : KeyAgreementAlgorithm.DiffieHellmanModp14,
                        Type = param->header.dwMagic == BCRYPT_DH_PRIVATE_MAGIC ? AsymmetricKeyType.Private : AsymmetricKeyType.Public,
                        CacheExpiry = expiry
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

                key.Factor = Copy(Factor.Span);
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
                key = (DiffieHellmanKey)PublicKey;

                keyType = BCRYPT_DH_PUBLIC_BLOB;
                dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
                structSize = sizeof(BCRYPT_DH_KEY_BLOB_HEADER) + (key.KeyLength * 3);
            }

            Factor = incoming.Factor.ToArray();

            using (var rented = CryptoPool.Rent<byte>(structSize))
            {
                rented.Memory.Span.Clear();

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

                    BCryptImportKeyPair(_hAlgorithm, IntPtr.Zero, keyType, ref hKey, pbInput, structSize).CheckSuccess();
                }
            }
        }

        public void ImportPartnerKey(IExchangeKey incoming)
        {
            ImportKey(incoming as DiffieHellmanKey, ref _hPublicKey);
        }

        public unsafe ReadOnlyMemory<byte> GenerateAgreement()
        {
            if (_hPublicKey == IntPtr.Zero)
            {
                throw new NotSupportedException("A partner key must be imported first");
            }

            int status;

            if (_phAgreedSecret != IntPtr.Zero)
            {
                BCryptDestroySecret(_phAgreedSecret).CheckSuccess();
            }

            _phAgreedSecret = IntPtr.Zero;
            BCryptSecretAgreement(_hPrivateKey, _hPublicKey, ref _phAgreedSecret).CheckSuccess();

            int pcbResult = 0;
            BCryptDeriveKey(_phAgreedSecret, BCRYPT_KDF_RAW_SECRET, null, null, 0, ref pcbResult).CheckSuccess();

            var pbDerivedKey = new byte[pcbResult];

            fixed (byte* pDerivedKey = &MemoryMarshal.GetReference(pbDerivedKey.AsSpan()))
            {
                BCryptDeriveKey(_phAgreedSecret, BCRYPT_KDF_RAW_SECRET, null, pDerivedKey, pbDerivedKey.Length, ref pcbResult).CheckSuccess();

            }

            pbDerivedKey.AsSpan().Reverse();

            return pbDerivedKey;
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
            //if (_hAlgorithm != IntPtr.Zero)
            //{
            //    BCryptCloseAlgorithmProvider(_hAlgorithm);
            //}

            if (_hPrivateKey != IntPtr.Zero)
            {
                BCryptDestroyKey(_hPrivateKey);
            }

            if (_hPublicKey != IntPtr.Zero)
            {
                BCryptDestroyKey(_hPublicKey);
            }

            if (_phAgreedSecret != IntPtr.Zero)
            {
                BCryptDestroySecret(_phAgreedSecret);
            }
        }

        ~BCryptDiffieHellman() => Dispose(false);
    }
}
