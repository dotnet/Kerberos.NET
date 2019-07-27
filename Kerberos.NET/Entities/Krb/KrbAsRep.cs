using Kerberos.NET.Asn1;
using Kerberos.NET.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kerberos.NET.Entities
{
    public partial class KrbAsRep : IAsn1ApplicationEncoder<KrbAsRep>
    {
        public KrbAsRep()
        {
            MessageType = MessageType.KRB_AS_REP;
        }

        public KrbAsRep DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return DecodeApplication(data);
        }

        public static async Task<KrbAsRep> GenerateTgt(
            IKerberosPrincipal principal,
            IEnumerable<KrbPaData> requirements,
            IRealmService realmService,
            KrbKdcReqBody asReq
        )
        {
            // This is approximately correct such that a client doesn't barf on it
            // The krbtgt Ticket structure is probably correct as far as AD thinks
            // Modulo the PAC, at least.

            var longTermKey = await principal.RetrieveLongTermCredential();
            var servicePrincipal = await realmService.Principals.RetrieveKrbtgt();
            var servicePrincipalKey = await servicePrincipal.RetrieveLongTermCredential();

            KrbAsRep asRep = await GenerateServiceTicket<KrbAsRep>(
                principal,
                longTermKey,
                servicePrincipal,
                servicePrincipalKey,
                realmService,
                addresses: asReq.Addresses
            );

            asRep.PaData = requirements.ToArray();

            return asRep;
        }
    }
}
