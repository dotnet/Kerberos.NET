// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    internal class S4UProvider : IS4UProvider
    {
        private readonly string upn;
        private readonly KeyTable keytab;
        private readonly Krb5Config config;
        private readonly ILoggerFactory logger;


        public S4UProvider(string upn, KeyTable keytab, Krb5Config config = null, ILoggerFactory logger = null)
        {
            this.upn = upn;
            this.keytab = keytab;
            this.config = config;
            this.logger = logger;
        }

        public async Task<ApplicationSessionContext> GetServiceTicket(RequestServiceTicket rst, CancellationToken cancellation)
        {
            var client = new KerberosClient(this.config, this.logger) { CacheInMemory = true };

            await client.Authenticate(new KeytabCredential(this.upn, this.keytab));

            return await client.GetServiceTicket(rst, cancellation);
        }
    }
}
