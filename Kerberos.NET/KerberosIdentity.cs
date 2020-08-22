// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public class KerberosIdentity : ClaimsIdentity
    {
        internal KerberosIdentity(
            IEnumerable<Claim> userClaims,
            string authenticationType,
            string nameType,
            string roleType,
            IEnumerable<Restriction> restrictions,
            ValidationActions validationMode,
            string apRep
        )
            : base(userClaims, authenticationType, nameType, roleType)
        {
            this.Restrictions = restrictions.GroupBy(r => r.Type).ToDictionary(r => r.Key, r => r.ToList().AsEnumerable());
            this.ValidationMode = validationMode;
            this.ApRep = apRep;
        }

        public IDictionary<AuthorizationDataType, IEnumerable<Restriction>> Restrictions { get; }

        public ValidationActions ValidationMode { get; }

        public string ApRep { get; }
    }
}