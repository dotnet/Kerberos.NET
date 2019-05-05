using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public class Checksum
    {
        private const int ChecksumContainsDelegationType = 0x8003;

        public Checksum Decode(Asn1Element element)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        ChecksumType = node[0].AsInt();
                        break;
                    case 1:
                        if (ChecksumType == ChecksumContainsDelegationType)
                        {
                            Delegation = new DelegationInfo().Decode(node[0].Value);
                        }
                        break;
                }
            }

            return this;
        }

        public int ChecksumType;

        public DelegationInfo Delegation;
    }
}
