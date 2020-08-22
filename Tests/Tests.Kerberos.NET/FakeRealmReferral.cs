// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Entities;
using Kerberos.NET.Server;

namespace Tests.Kerberos.NET
{
    internal class FakeRealmReferral : IRealmReferral
    {
        private readonly KrbKdcReqBody body;

        public FakeRealmReferral(KrbKdcReqBody body)
        {
            this.body = body;
        }

        public IKerberosPrincipal Refer()
        {
            var fqn = this.body.SName.FullyQualifiedName;
            var predictedRealm = fqn.Substring(fqn.IndexOf('.') + 1);

            var krbName = KrbPrincipalName.FromString($"krbtgt/{predictedRealm}");

            return new FakeKerberosPrincipal(krbName.FullyQualifiedName);
        }
    }
}