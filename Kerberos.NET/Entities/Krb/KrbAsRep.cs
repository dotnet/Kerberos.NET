// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Asn1;
using Kerberos.NET.Server;

namespace Kerberos.NET.Entities
{
    public partial class KrbAsRep : IAsn1ApplicationEncoder<KrbAsRep>
    {
        public KrbAsRep()
        {
            this.MessageType = MessageType.KRB_AS_REP;
        }

        public KrbAsRep DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return DecodeApplication(data);
        }

        public static KrbAsRep GenerateTgt(
            ServiceTicketRequest rst,
            IRealmService realmService
        )
        {
            if (realmService == null)
            {
                throw new ArgumentNullException(nameof(realmService));
            }

            rst.Compatibility = realmService.Settings.Compatibility;

            // This is approximately correct such that a client doesn't barf on it
            // The krbtgt Ticket structure is probably correct as far as AD thinks
            // Modulo the PAC, at least.

            if (string.IsNullOrWhiteSpace(rst.RealmName))
            {
                // TODO: Possible bug. Realm service now has multiple krbtgt's so the name is always set
                // to the name of our (cloud) KDC name. Will this be an issue for trust ticket or mcticket?
                rst.RealmName = realmService.Name;
            }

            KrbPrincipalName krbtgtName = KrbPrincipalName.WellKnown.Krbtgt(rst.RealmName);

            if (rst.ServicePrincipal == null)
            {
                rst.ServicePrincipal = realmService.Principals.Find(krbtgtName, rst.RealmName);
            }

            if (rst.ServicePrincipalKey == null)
            {
                rst.ServicePrincipalKey = rst.ServicePrincipal.RetrieveLongTermCredential();
            }

            if (rst.KdcAuthorizationKey == null)
            {
                // Not using rst.ServicePrincipal because it may not actually be krbtgt

                var krbtgt = realmService.Principals.Find(krbtgtName, rst.RealmName);

                rst.KdcAuthorizationKey = krbtgt.RetrieveLongTermCredential();
            }

            rst.Now = realmService.Now();
            rst.MaximumTicketLifetime = realmService.Settings.SessionLifetime;
            rst.MaximumRenewalWindow = realmService.Settings.MaximumRenewalWindow;

            if (rst.Flags == 0)
            {
                rst.Flags = DefaultFlags;
            }

            return GenerateServiceTicket<KrbAsRep>(rst);
        }
    }
}
