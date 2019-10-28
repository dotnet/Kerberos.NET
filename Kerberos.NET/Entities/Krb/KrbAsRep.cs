using Kerberos.NET.Asn1;
using Kerberos.NET.Server;
using System;
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
            ServiceTicketRequest rst,
            IRealmService realmService
        )
        {
            // This is approximately correct such that a client doesn't barf on it
            // The krbtgt Ticket structure is probably correct as far as AD thinks
            // Modulo the PAC, at least.

            if (string.IsNullOrWhiteSpace(rst.RealmName))
            {
                rst.RealmName = realmService.Name;
            }

            if (rst.ServicePrincipal == null)
            {
                rst.ServicePrincipal = await realmService.Principals.RetrieveKrbtgt();
            }

            if (rst.ServicePrincipalKey == null)
            {
                rst.ServicePrincipalKey = await rst.ServicePrincipal.RetrieveLongTermCredential();
            }

            var now = realmService.Now();

            rst.Now = now;
            rst.RenewTill = now + realmService.Settings.MaximumRenewalWindow;
            rst.StartTime = now - realmService.Settings.MaximumSkew;
            rst.EndTime = now + realmService.Settings.SessionLifetime;

            if (rst.Flags == 0)
            {
                rst.Flags = DefaultFlags;
            }

            return await GenerateServiceTicket<KrbAsRep>(rst);
        }
    }
}
