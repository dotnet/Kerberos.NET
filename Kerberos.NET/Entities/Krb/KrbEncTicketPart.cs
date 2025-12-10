// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncTicketPart : IAsn1ApplicationEncoder<KrbEncTicketPart>
    {
        public MessageType MessageType => (MessageType)(-1);

        public KrbEncTicketPart DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return DecodeApplication(data);
        }

        public bool TryGetPac(out PrivilegedAttributeCertificate pac)
        {
            pac = null;

            KrbAuthorizationData adIfRelevantEntry = this.AuthorizationData?.FirstOrDefault(ad => ad.Type == AuthorizationDataType.AdIfRelevant);
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
