
using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbAuthenticator
    {
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 2);

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            writer.PushSequence(ApplicationTag);

            this.Encode(writer);

            writer.PopSequence(ApplicationTag);

            var span = writer.EncodeAsSpan();

            return new ReadOnlyMemory<byte>(span.ToArray());
        }
    }
}
