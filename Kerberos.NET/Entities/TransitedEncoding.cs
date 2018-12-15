using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public enum TransitedEncodingType : long
    {
        DomainX500Compress = 1
    }

    public class TransitedEncoding
    {
        public TransitedEncoding(Asn1Element element)
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
        }

        public TransitedEncodingType Type { get; private set; }

        public string Contents { get; private set; }
    }
}
