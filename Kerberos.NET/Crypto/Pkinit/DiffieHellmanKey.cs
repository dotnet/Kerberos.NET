// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Asn1;

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

        public ReadOnlyMemory<byte> PublicComponent { get; set; }

        public ReadOnlyMemory<byte> PrivateComponent { get; set; }

        public ReadOnlyMemory<byte> EncodePublicKey()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.WriteKeyParameterInteger(this.PublicComponent.Span);

                return writer.EncodeAsMemory();
            }
        }

        public static DiffieHellmanKey ParsePublicKey(ReadOnlyMemory<byte> data, int keyLength)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);

            var bytes = reader.ReadIntegerBytes();

            return new DiffieHellmanKey { PublicComponent = bytes.DepadLeft().PadRight(keyLength) };
        }
    }
}