// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //
    // DO NOT USE THIS
    //
    // THIS IS NOT PRODUCTION-WORTHY CODE
    // IT IS UNSAFE AND UNTESTED
    //
    // DO NOT USE THIS
    //
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /// <summary>
    /// DO NOT USE THIS
    ///
    /// THIS IS NOT PRODUCTION-WORTHY CODE
    /// IT IS UNSAFE AND UNTESTED
    ///
    /// DO NOT USE THIS
    /// </summary>
    public abstract class ManagedDiffieHellman : IKeyAgreement
    {
        private readonly int keyLength;

        private readonly BigInteger prime;
        private readonly BigInteger generator;
        private readonly BigInteger factor;
        private readonly BigInteger x;

        private readonly BigInteger y;

        private BigInteger partnerKey;
        private bool disposedValue;

        public ManagedDiffieHellman(ReadOnlyMemory<byte> prime, ReadOnlyMemory<byte> generator, ReadOnlyMemory<byte> factor)
        {
            this.keyLength = prime.Length;

            this.prime = ParseBigInteger(prime);
            this.generator = ParseBigInteger(generator);
            this.factor = ParseBigInteger(factor);

            this.x = this.GeneratePrime();

            this.y = BigInteger.ModPow(this.generator, this.x, this.prime);

            this.PublicKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Public,
                Generator = this.Depad(this.generator.ToByteArray(), true),
                Modulus = this.Depad(this.prime.ToByteArray(), true),
                PublicComponent = this.Depad(this.y.ToByteArray(), true),
                Factor = this.Depad(this.factor.ToByteArray(), true),
                KeyLength = prime.Length
            };

            this.PrivateKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Private,
                Generator = this.Depad(this.generator.ToByteArray(), true),
                Modulus = this.Depad(this.prime.ToByteArray(), true),
                PublicComponent = this.Depad(this.y.ToByteArray(), true),
                Factor = this.Depad(this.factor.ToByteArray(), true),
                PrivateComponent = this.Depad(this.x.ToByteArray(), true),
                KeyLength = prime.Length
            };
        }

        private BigInteger GeneratePrime()
        {
            // RSA's P and Q parameters are prime, but len(P+Q) = keylength
            // so generate an RSA key twice as large as required and just
            // use P as the prime.

            // P in RSA is a safer prime than primes used in DH so it's
            // good enough here, though it's costlier to generate.

            using (var alg = new RSACryptoServiceProvider(this.keyLength * 2 * 8))
            {
                var rsa = alg.ExportParameters(true);

                return ParseBigInteger(rsa.P);
            }
        }

        private static BigInteger ParseBigInteger(ReadOnlyMemory<byte> arr, bool reverse = false)
        {
            var pv = arr.ToArray();

            if (reverse)
            {
                Array.Reverse(pv);
            }

            if (pv[pv.Length - 1] != 0)
            {
                var copy = new byte[pv.Length + 1];

                pv.CopyTo(copy, 0);

                pv = copy;
            }

            return new BigInteger(pv);
        }

        public IExchangeKey PublicKey { get; }

        public IExchangeKey PrivateKey { get; }

        public ReadOnlyMemory<byte> GenerateAgreement()
        {
            var z = BigInteger.ModPow(this.partnerKey, this.x, this.prime);

            var ag = z.ToByteArray();

            var agreement = this.Depad(ag, true);

            agreement = Pad(agreement, this.keyLength);

            return agreement;
        }

        public void ImportPartnerKey(IExchangeKey publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }

            this.partnerKey = ParseBigInteger(publicKey.PublicComponent, true);
        }

        private byte[] Depad(byte[] data, bool reverse = false)
        {
            var mem = new Memory<byte>(data);

            for (var i = data.Length - 1; i > 0; i--)
            {
                if (data[i] == 0 && mem.Length > this.keyLength)
                {
                    mem = mem.Slice(0, i);
                }
                else
                {
                    break;
                }
            }

            var arr = mem.ToArray();

            if (reverse)
            {
                Array.Reverse(arr);
            }

            return arr;
        }

        private static byte[] Pad(byte[] agreement, int keyLength)
        {
            var copy = new byte[keyLength];

            agreement.CopyTo(copy, keyLength - agreement.Length);

            return copy;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
