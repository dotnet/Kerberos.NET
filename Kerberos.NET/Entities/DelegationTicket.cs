using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public class DelegationTicket
    {
        public DelegationTicket Decode(Asn1Element sequence)
        {
            Credential = new KrbCred().Decode(sequence[0]);

            return this;
        }

        public KrbCred Credential;
    }
}
