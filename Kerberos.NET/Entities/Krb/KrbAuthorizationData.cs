// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    public partial class KrbAuthorizationData
    {
        public IEnumerable<KrbAuthorizationData> DecodeAdIfRelevant()
        {
            if (this.Type != AuthorizationDataType.AdIfRelevant)
            {
                throw new InvalidOperationException($"Cannot decode AdIfRelevant because type is {this.Type}");
            }

            var adIfRelevant = KrbAuthorizationDataSequence.Decode(this.Data);

            return adIfRelevant.AuthorizationData;
        }
    }
}