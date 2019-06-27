using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public enum TransitedEncodingType : long
    {
        DomainX500Compress = 1
    }

    public class TransitedEncoding
    {
        public TransitedEncoding Decode(Asn1Element element)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];
                switch (node.ContextSpecificTag)
                {
                    case 0:
                        Type = (TransitedEncodingType)node[0].AsLong();
                        break;
                    case 1:
                        Contents = node[0].AsString();
                        break;
                }
            }

            return this;
        }

        public TransitedEncodingType Type;

        public string Contents;
    }
}
