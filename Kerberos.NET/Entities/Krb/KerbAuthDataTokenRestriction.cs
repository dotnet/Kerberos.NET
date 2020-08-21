// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public class KerbAuthDataTokenRestriction : Restriction
    {
        public KerbAuthDataTokenRestriction(KrbAuthorizationData authz)
            : base(authz?.Type ?? 0, AuthorizationDataType.KerbAuthDataTokenRestrictions)
        {
            var restriction = KrbAuthorizationDataSequence.Decode(authz.Data);

            foreach (var data in restriction.AuthorizationData)
            {
                this.RestrictionType = (int)data.Type;
                this.Restriction = new LsapTokenInfoIntegrity(data.Data);
                break;
            }
        }

        public int RestrictionType { get; }

        public LsapTokenInfoIntegrity Restriction { get; }
    }
}