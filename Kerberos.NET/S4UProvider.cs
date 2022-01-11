// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    internal class S4UProvider : IS4UProvider
    {
        private readonly KerberosClient client;
        private readonly KerberosCredential credential;
        private readonly DecryptedKrbApReq krbApReq;

        public S4UProvider(KerberosClient client, KerberosCredential credential, DecryptedKrbApReq krbApReq)
        {
            this.client = client;
            this.credential = credential;
            this.krbApReq = krbApReq;
        }

        public async Task<ApplicationSessionContext> GetServiceTicket(RequestServiceTicket rst, CancellationToken cancellation)
        {
            rst.S4uTarget = null;
            rst.S4uTicket = this.krbApReq.EncryptedTicket;
            rst.KdcOptions |= KdcOptions.CNameInAdditionalTicket;

            bool retried = false;

            while (true)
            {
                try
                {
                    return await client.GetServiceTicket(rst, cancellation);
                }
                catch (InvalidOperationException)
                {
                    if (retried)
                    {
                        break;
                    }

                    await client.Authenticate(this.credential);
                    retried = true;
                }
            }

            return null;
        }
    }
}
