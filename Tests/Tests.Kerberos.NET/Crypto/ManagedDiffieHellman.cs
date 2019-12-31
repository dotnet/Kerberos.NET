using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public class ManagedDiffieHellmanOakley14 : ManagedDiffieHellman
    {
        public ManagedDiffieHellmanOakley14()
            : base(Oakley.Group14.PrimeLittleEndian, Oakley.Group14.GeneratorLittleEndian, Oakley.Group14.Factor)
        {
        }
    }

    public class ManagedDiffieHellmanOakley2 : ManagedDiffieHellman
    {
        public ManagedDiffieHellmanOakley2()
            : base(Oakley.Group2.PrimeLittleEndian, Oakley.Group2.GeneratorLittleEndian, Oakley.Group2.Factor)
        {
        }

    }

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

    public abstract class ManagedDiffieHellman : IKeyAgreement
    {
        private readonly int keyLength;

        private readonly BigInteger prime;
        private readonly BigInteger generator;
        private readonly BigInteger factor;
        private readonly BigInteger x;

        private readonly BigInteger y;

        private BigInteger partnerKey;

        public ManagedDiffieHellman(ReadOnlyMemory<byte> prime, ReadOnlyMemory<byte> generator, ReadOnlyMemory<byte> factor)
        {
            this.keyLength = prime.Length;

            this.prime = ParseBigInteger(prime);
            this.generator = ParseBigInteger(generator);
            this.factor = ParseBigInteger(factor);

            this.x = GeneratePrime();

            y = BigInteger.ModPow(this.generator, this.x, this.prime);

            PublicKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Public,
                Generator = Depad(this.generator.ToByteArray(), true),
                Modulus = Depad(this.prime.ToByteArray(), true),
                Public = Depad(y.ToByteArray(), true),
                Factor = Depad(this.factor.ToByteArray(), true),
                KeyLength = prime.Length
            };

            PrivateKey = new DiffieHellmanKey
            {
                Type = AsymmetricKeyType.Private,
                Generator = Depad(this.generator.ToByteArray(), true),
                Modulus = Depad(this.prime.ToByteArray(), true),
                Public = Depad(y.ToByteArray(), true),
                Factor = Depad(this.factor.ToByteArray(), true),
                Private = Depad(x.ToByteArray(), true),
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

            using (var alg = RSA.Create(keyLength * 2 * 8))
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

            if (pv[^1] != 0)
            {
                var copy = new byte[pv.Length + 1];

                pv.CopyTo(copy, 0);

                pv = copy;
            }

            return new BigInteger(pv);
        }

        public IExchangeKey PublicKey { get; }

        public IExchangeKey PrivateKey { get; }

        public void Dispose() { }

        public ReadOnlyMemory<byte> GenerateAgreement()
        {
            var z = BigInteger.ModPow(partnerKey, x, prime);

            var ag = z.ToByteArray();

            var agreement = Depad(ag, true);

            agreement = Pad(agreement, keyLength);

            return agreement;
        }

        public void ImportPartnerKey(IExchangeKey publicKey)
        {
            this.partnerKey = ParseBigInteger(publicKey.Public, true);
        }

        private byte[] Depad(byte[] data, bool reverse = false)
        {
            var mem = new Memory<byte>(data);

            for (var i = data.Length - 1; i > 0; i--)
            {
                if (data[i] == 0 && mem.Length > keyLength)
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
    }
}
