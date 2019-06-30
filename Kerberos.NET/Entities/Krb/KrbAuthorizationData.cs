using System;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    public partial struct KrbAuthorizationData
    {
        public IEnumerable<KrbAuthorizationData> DecodeAdIfRelevant()
        {
            if (Type != AuthorizationDataType.AdIfRelevant)
            {
                throw new InvalidOperationException($"Cannot decode AdIfRelevant because type is {Type}");
            }

            var adIfRelevant = KrbAuthorizationDataSequence.Decode(Data);

            return adIfRelevant.AuthorizationData;
        }
    }
}
