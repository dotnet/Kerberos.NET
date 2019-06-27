using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public class KrbPaData
    {
        public int Type { get; set; }

        public byte[] Value { get; set; }

        /*

            PA-DATA         ::= SEQUENCE {
                -- NOTE: first tag is [1], not [0]
                padata-type     [1] Int32,
                padata-value    [2] OCTET STRING -- might be encoded AP-REQ
            }

        */

        public KrbPaData Decode(Asn1Element element)
        {
            var paData = this;

            for (var i = 0; i < element.Count; i++)
            {
                var child = element[i];

                switch (child.ContextSpecificTag)
                {
                    case 1:
                        paData.Type = child[0].AsInt();
                        break;
                    case 2:
                        paData.Value = child.AsOctetString();
                        break;
                }
            }

            return paData;
        }
    }
}
