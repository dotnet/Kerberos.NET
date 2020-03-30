using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class HttpKerberosTransportTests
    {
        [TestMethod]
        public async Task HttpsTransportReceivesSuccess()
        {
            var transport = new HandledHttpsKerberosTransport(new SuccessKdcMessageDelegatingHandler());

            var asReq = KrbAsReq.CreateAsReq(new KerberosPasswordCredential(UserUpn, "P@ssw0rd!"), AuthenticationOptions.Forwardable);

            var response = await transport.SendMessage<KrbAsRep>("adasdf", asReq.EncodeApplication());

            Assert.IsNotNull(response);
        }

        [TestMethod, ExpectedException(typeof(HttpRequestException))]
        public async Task HttpsTransportReceivesFailure()
        {
            var transport = new HandledHttpsKerberosTransport(new FailureKdcMessageDelegatingHandler());

            var asReq = KrbAsReq.CreateAsReq(new KerberosPasswordCredential(UserUpn, "P@ssw0rd!"), AuthenticationOptions.Forwardable);

            await transport.SendMessage<KrbAsRep>("adasdf", asReq.EncodeApplication());
        }

        private class HandledHttpsKerberosTransport : HttpsKerberosTransport
        {
            private readonly DelegatingHandler handler;

            public HandledHttpsKerberosTransport(DelegatingHandler handler)
            {
                this.handler = handler;
            }

            protected override HttpClient Client => new HttpClient(handler);
        }

        internal static readonly byte[] TgtKey = new byte[] {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };

        private const string Realm = "corp.test.internal";
        private const string UserUpn = "user@test.internal";

        private class FailureKdcMessageDelegatingHandler : DelegatingHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var response = new HttpResponseMessage(HttpStatusCode.BadRequest);

                return Task.FromResult(response);
            }
        }

        private class SuccessKdcMessageDelegatingHandler : DelegatingHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var realmService = new FakeRealmService(Realm);
                var principal = realmService.Principals.Find(KrbPrincipalName.FromString(UserUpn));

                var principalKey = principal.RetrieveLongTermCredential();

                var rst = new ServiceTicketRequest
                {
                    Principal = principal,
                    EncryptedPartKey = principalKey,
                    ServicePrincipalKey = new KerberosKey(key: TgtKey, etype: EncryptionType.AES256_CTS_HMAC_SHA1_96)
                };

                var tgt = KrbAsRep.GenerateTgt(rst, realmService);

                var encoded = tgt.EncodeApplication();

                var response = new Memory<byte>(new byte[encoded.Length + 4]);
                Endian.ConvertToBigEndian(encoded.Length, response.Slice(0, 4));
                encoded.CopyTo(response.Slice(4));

                var kdcMessage = new KdcProxyMessage
                {
                    KerbMessage = response
                };

                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(kdcMessage.Encode().ToArray())
                });
            }
        }
    }
}
