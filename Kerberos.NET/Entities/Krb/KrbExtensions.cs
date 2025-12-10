// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Linq;

namespace Kerberos.NET.Entities
{
    public static class KrbExtensions
    {
        public static bool TryGetPac(this KrbEncTicketPart encTicketPart, out PrivilegedAttributeCertificate pac)
        {
            pac = null;

            KrbAuthorizationData adIfRelevantEntry = encTicketPart.AuthorizationData?.FirstOrDefault(ad => ad.Type == AuthorizationDataType.AdIfRelevant);
            if (adIfRelevantEntry == null)
            {
                return false;
            }

            KrbAuthorizationDataSequence adIfRelevant = null;
            try
            {
                adIfRelevant = KrbAuthorizationDataSequence.Decode(adIfRelevantEntry.Data);
            }
            catch
            {
                return false;
            }

            KrbAuthorizationData pacEntry = adIfRelevant?.AuthorizationData?.First(ad => ad.Type == AuthorizationDataType.AdWin2kPac);
            if (pacEntry == null)
            {
                return false;
            }

            try
            {
                pac = new PrivilegedAttributeCertificate(pacEntry);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
