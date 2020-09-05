// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
    public abstract class CryptoPal
    {
        protected static bool IsWindows => OSPlatform.IsWindows;

        protected static bool IsLinux => OSPlatform.IsLinux;

        protected static bool IsOsX => OSPlatform.IsOsX;

        public static CryptoPal Platform => LazyPlatform.Value;

        private static readonly Lazy<CryptoPal> LazyPlatform
            = new Lazy<CryptoPal>(() => CreatePal());

        private static Func<CryptoPal> injectedPal;

        public static void RegisterPal(Func<CryptoPal> palFunc)
        {
            injectedPal = palFunc ?? throw new InvalidOperationException("Cannot register a null PAL");
        }

        private static CryptoPal CreatePal()
        {
            var injected = injectedPal;

            if (injected != null)
            {
                return injected();
            }

            if (IsWindows)
            {
                return new WindowsCryptoPal();
            }

            if (IsLinux)
            {
                return new LinuxCryptoPal();
            }

            if (IsOsX)
            {
                return new OSXCryptoPal();
            }

            throw PlatformNotSupported();
        }

#if WEAKCRYPTO
        public abstract IHashAlgorithm Md4();

        public abstract IHashAlgorithm Md5();

        public abstract IHmacAlgorithm HmacMd5();
#endif

        public abstract IHmacAlgorithm HmacSha1();

        public abstract IKeyDerivationAlgorithm Rfc2898DeriveBytes();

        public abstract IHashAlgorithm Sha1();

        public abstract IHashAlgorithm Sha256();

        public abstract ISymmetricAlgorithm Aes();

        public abstract IKeyAgreement DiffieHellmanP256();

        public abstract IKeyAgreement DiffieHellmanP384();

        public abstract IKeyAgreement DiffieHellmanP521();

        public abstract IKeyAgreement DiffieHellmanModp2();

        public abstract IKeyAgreement DiffieHellmanModp2(IExchangeKey privateKey);

        public abstract IKeyAgreement DiffieHellmanModp14();

        public abstract IKeyAgreement DiffieHellmanModp14(IExchangeKey privateKey);

        protected static PlatformNotSupportedException PlatformNotSupported(string algorithm = "CryptoPal")
        {
            throw new PlatformNotSupportedException(
                $"A crypto implementation of {algorithm} does not exist for {Environment.OSVersion.Platform}"
            );
        }
    }
}
