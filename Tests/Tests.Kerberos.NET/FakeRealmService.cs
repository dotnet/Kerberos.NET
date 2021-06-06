// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Configuration;
using Kerberos.NET.Server;

namespace Tests.Kerberos.NET
{
    public class FakeRealmService : IRealmService
    {
        public FakeRealmService(string realm, Krb5Config config = null)
        {
            this.Name = realm;
            this.Configuration = config ?? Krb5Config.Kdc();
        }

        public IRealmSettings Settings => new FakeRealmSettings();

        public IPrincipalService Principals => new FakePrincipalService(this.Name);

        public string Name { get; }

        public DateTimeOffset Now() => DateTimeOffset.UtcNow;

        public ITrustedRealmService TrustedRealms => new FakeTrustedRealms(this.Name);

        public Krb5Config Configuration { get; }
    }
}
