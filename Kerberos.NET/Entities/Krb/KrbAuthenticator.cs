// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbAuthenticator
    {
        public KrbAuthenticator()
        {
            this.AuthenticatorVersionNumber = 5;
        }

        [Obsolete("Use to property named to match the spec `CRealm`.")]
        public string Realm { get => this.CRealm; set => this.CRealm = value; }
    }
}
