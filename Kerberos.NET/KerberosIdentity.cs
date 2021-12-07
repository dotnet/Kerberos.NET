// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Kerberos.NET.Crypto;
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
            DecryptedKrbApReq krbApReq
        )
            : base(userClaims, authenticationType, nameType, roleType)
        {
            this.Restrictions = restrictions.GroupBy(r => r.Type).ToDictionary(r => r.Key, r => r.ToList().AsEnumerable());
            this.ValidationMode = validationMode;

            if (krbApReq.Options.HasFlag(ApOptions.MutualRequired))
            {
                var apRepEncoded = krbApReq.CreateResponseMessage().EncodeApplication();

                this.ApRep = Convert.ToBase64String(apRepEncoded.ToArray());
            }

            this.SessionKey = krbApReq.SessionKey.GetKey();
        }

        public IDictionary<AuthorizationDataType, IEnumerable<Restriction>> Restrictions { get; }

        public ValidationActions ValidationMode { get; }

        public ReadOnlyMemory<byte> SessionKey { get; }

        public string ApRep { get; }
    }
}
