// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET
{
    internal class S4UProviderFactory : IS4UProviderFactory
    {
        private readonly KerberosClient client;
        private readonly KerberosCredential credential;

        public S4UProviderFactory(string upn, KeyTable keytab, KerberosClient delegationClient, Krb5Config config = null, ILoggerFactory logger = null)
        {
            this.client = KerberosClient.CopyOrCreate(delegationClient, config, logger);
            this.credential = new KeytabCredential(upn, keytab);
        }

        public IS4UProvider CreateProvider(DecryptedKrbApReq krbApReq) => new S4UProvider(this.client, this.credential, krbApReq);
    }
}
