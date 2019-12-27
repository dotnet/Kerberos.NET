using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbDiffieHellmanDomainParameters
    {
        public static KrbDiffieHellmanDomainParameters DecodeSpecial(ReadOnlyMemory<byte> data)
        {
            var decoded = Decode(data);

            decoded.P = new AsnReader(decoded.P, AsnEncodingRules.DER).ReadIntegerBytes().DepadLeft();
            decoded.G = new AsnReader(decoded.G, AsnEncodingRules.DER).ReadIntegerBytes().DepadLeft();
            decoded.Q = new AsnReader(decoded.Q, AsnEncodingRules.DER).ReadIntegerBytes().DepadLeft();

            return decoded;
        }

        public ReadOnlyMemory<byte> EncodeSpecial()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                var tag = Asn1Tag.Sequence;

                writer.PushSequence(tag);

                writer.WriteKeyParameterInteger(P.Span);
                writer.WriteKeyParameterInteger(G.Span);
                writer.WriteKeyParameterInteger(Q.Span);

                if (Asn1Extension.HasValue(J))
                {
                    writer.WriteKeyParameterInteger(J.Value.Span);
                }

                if (Asn1Extension.HasValue(ValidationParameters))
                {
                    ValidationParameters?.Encode(writer);
                }

                writer.PopSequence(tag);

                return writer.EncodeAsMemory();
            }
        }

        private static ReadOnlyMemory<byte> DepadRight(ReadOnlyMemory<byte> data)
        {
            var result = data;

            for (var i = data.Length - 1; i > 0; i--)
            {
                if (data.Span[i] == 0)
                {
                    result = result.Slice(0, i);
                }
                else
                {
                    break;
                }
            }

            return result;
        }

        private static ReadOnlyMemory<byte> Pad(ReadOnlyMemory<byte> pv)
        {
            if (pv.Span[0] != 0)
            {
                var copy = new Memory<byte>(new byte[pv.Length + 1]);

                pv.CopyTo(copy.Slice(1));

                pv = copy;
            }

            return pv;
        }

        internal static KrbDiffieHellmanDomainParameters FromKeyAgreement(IKeyAgreement agreement)
        {
            if (!(agreement.PublicKey is DiffieHellmanKey pk))
            {
                throw new ArgumentException("Not a DH key agreement");
            }

            return new KrbDiffieHellmanDomainParameters
            {
                P = Pad(pk.Modulus),
                G = DepadRight(pk.Generator),
                Q = pk.Factor
            };
        }
    }
}
