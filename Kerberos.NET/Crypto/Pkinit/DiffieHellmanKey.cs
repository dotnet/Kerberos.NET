using Kerberos.NET.Asn1;
using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Crypto
{
    public class DiffieHellmanKey : IExchangeKey
    {
        public AsymmetricKeyType Type { get; set; }

        public KeyAgreementAlgorithm Algorithm { get; set; }

        public DateTimeOffset? CacheExpiry { get; set; }

        public int KeyLength { get; set; }

        public ReadOnlyMemory<byte> Modulus { get; set; }

        public ReadOnlyMemory<byte> Generator { get; set; }

        public ReadOnlyMemory<byte> Factor { get; set; }

        public ReadOnlyMemory<byte> Public { get; set; }

        public ReadOnlyMemory<byte> Private { get; set; }

        public ReadOnlyMemory<byte> EncodePublicKey()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.WriteKeyParameterInteger(Public.Span);

                return writer.EncodeAsMemory();
            }
        }

        public static DiffieHellmanKey ParsePublicKey(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);

            var bytes = reader.ReadIntegerBytes();

            return new DiffieHellmanKey { Public = bytes.DepadLeft() };
        }
    }
}
