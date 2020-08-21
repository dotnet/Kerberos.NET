// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public class ETypeNegotiationRestriction : Restriction
    {
        public ETypeNegotiationRestriction(KrbAuthorizationData authz)
            : base(authz?.Type ?? 0, AuthorizationDataType.AdETypeNegotiation)
        {
            var etypes = KrbETypeList.Decode(authz.Data);

            this.ETypes = new List<EncryptionType>(etypes.List);
        }

        public IEnumerable<EncryptionType> ETypes { get; }
    }
}