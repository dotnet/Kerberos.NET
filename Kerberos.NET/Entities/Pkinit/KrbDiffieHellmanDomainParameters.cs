using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbDiffieHellmanDomainParameters
    {
        public static KrbDiffieHellmanDomainParameters DecodeSpecial(ReadOnlyMemory<byte> data)
        {
            var decoded = Decode(data);

            decoded.P = new AsnReader(decoded.P, AsnEncodingRules.DER).ReadIntegerBytes();
            decoded.G = new AsnReader(decoded.G, AsnEncodingRules.DER).ReadIntegerBytes();
            decoded.Q = new AsnReader(decoded.Q, AsnEncodingRules.DER).ReadIntegerBytes();

            return decoded;
        }

        public ReadOnlyMemory<byte> EncodeSpecial()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                var tag = Asn1Tag.Sequence;

                writer.PushSequence(tag);

                //writer.WriteIntegerUnsigned(P.Span);
                //writer.WriteIntegerUnsigned(G.Span);
                //writer.WriteIntegerUnsigned(Q.Span);

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
    }
}
