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
            IKerberosPrincipal principal,
            IRealmService realmService,
            ServiceTicketRequest rst = default
        )
        {
            // This is approximately correct such that a client doesn't barf on it
            // The krbtgt Ticket structure is probably correct as far as AD thinks
            // Modulo the PAC, at least.

            rst.RealmName = realmService.Name;
            rst.Principal = principal;

            rst.EncryptedPartKey = await principal.RetrieveLongTermCredential();

            rst.ServicePrincipal = await realmService.Principals.RetrieveKrbtgt();

            if (rst.ServicePrincipalKey == null)
            {
                rst.ServicePrincipalKey = await rst.ServicePrincipal.RetrieveLongTermCredential();
            }

            var now = realmService.Now();

            rst.Now = now;
            rst.RenewTill = now + realmService.Settings.MaximumRenewalWindow;
            rst.StartTime = now - realmService.Settings.MaximumSkew;
            rst.EndTime = now + realmService.Settings.SessionLifetime;

            rst.Flags = DefaultFlags;

            return await GenerateServiceTicket<KrbAsRep>(rst);
        }
    }
}
