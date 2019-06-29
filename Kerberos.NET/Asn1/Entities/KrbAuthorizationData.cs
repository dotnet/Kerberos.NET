
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Asn1.Entities
{
    public partial struct KrbAuthorizationData
    {
        public IEnumerable<KrbAuthorizationData> DecodeAdIfRelevant()
        {
            if (Type != AuthorizationDataType.AdIfRelevant)
            {
                throw new InvalidOperationException($"Cannot decode AdIfRelevant because type is {Type}");
            }

            var adIfRelevant = KrbAuthorizationDataSequence.Decode(this.Data, AsnEncodingRules.DER);

            return adIfRelevant.AuthorizationData;
        }

        public KrbAuthorizationData DecodePac()
        {
            if ((AuthorizationDataValueType)Type != AuthorizationDataValueType.AD_WIN2K_PAC)
            {
                throw new InvalidOperationException($"Cannot decode PAC because type is {Type}");
            }

            return this;
        }
    }
}
