using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class E2EKdcClientTest
    {
        [TestMethod]
        public async Task TestE2E()
        {
            var port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            using (KdcServiceListener listener = new KdcServiceListener(options))
            {
                _ = listener.Start();

                await RequestAndValidateTickets("administrator@corp.identityintervention.com", "P@ssw0rd!", $"127.0.0.1:{port}");

                listener.Stop();
            }
        }

        [TestMethod]
        public async Task TestU2U()
        {
            var port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            KdcServiceListener listener = new KdcServiceListener(options);

            _ = listener.Start();

            var kerbClientCred = new KerberosPasswordCredential("administrator@corp.identityintervention.com", "P@ssw0rd!");
            var client = new KerberosClient($"127.0.0.1:{port}");

            await client.Authenticate(kerbClientCred);

            var kerbServerCred = new KerberosPasswordCredential("u2u@corp.identityintervention.com", "P@ssw0rd!");
            var server = new KerberosClient($"127.0.0.1:{port}");

            await server.Authenticate(kerbClientCred);
            var serverTgt = server.TicketGrantingTicket.Ticket;

            var apReq = await client.GetServiceTicket("host/u2u", ApOptions.MutualRequired | ApOptions.UseSessionKey, serverTgt);

            Assert.IsNotNull(apReq);

            var decrypted = new DecryptedKrbApReq(apReq);

            Assert.IsNull(decrypted.Ticket);

            decrypted.Decrypt(server.TgtSessionKey.AsKey());

            decrypted.Validate(ValidationActions.All);

            Assert.IsNotNull(decrypted.Ticket);

            Assert.AreEqual("host/u2u/CORP.IDENTITYINTERVENTION.COM", decrypted.SName.FullyQualifiedName);

            listener.Stop();
        }

        [TestMethod, ExpectedException(typeof(TimeoutException))]
        public async Task TestReceiveTimeout()
        {
            var port = new Random().Next(20000, 40000);
            var log = new ExceptionTraceLog();

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm, slow: true),
                ReceiveTimeout = TimeSpan.FromMilliseconds(1),
                Log = log
            };

            options.Log.Enabled = true;
            options.Log.Level = LogLevel.Verbose;

            KdcServiceListener listener = new KdcServiceListener(options);

            _ = listener.Start();

            try
            {
                await RequestAndValidateTickets("administrator@corp.identityintervention.com", "P@ssw0rd!", $"127.0.0.1:{port}");
            }
            catch
            {
            }

            listener.Stop();

            var timeout = log.Exceptions.FirstOrDefault(e => e is TimeoutException);

            Assert.IsNotNull(timeout);

            throw timeout;
        }

        private static async Task RequestAndValidateTickets(string user, string password, string overrideKdc)
        {
            var kerbCred = new KerberosPasswordCredential(user, password);

            KerberosClient client = new KerberosClient(overrideKdc);

            await client.Authenticate(kerbCred);

            var ticket = await client.GetServiceTicket(
                "host/appservice.corp.identityintervention.com",
                ApOptions.MutualRequired
            );

            await ValidateTicket(ticket);

            await client.RenewTicket();

            ticket = await client.GetServiceTicket(
                "host/appservice.corp.identityintervention.com",
                ApOptions.MutualRequired
            );

            await ValidateTicket(ticket);
        }

        private static async Task ValidateTicket(KrbApReq ticket)
        {
            var encoded = ticket.EncodeApplication().ToArray();

            var authenticator = new KerberosAuthenticator(
                new KeyTable(
                    new KerberosKey(
                        "P@ssw0rd!",
                        principalName: new PrincipalName(
                            PrincipalNameType.NT_PRINCIPAL,
                            "CORP.IDENTITYINTERVENTION.com",
                            new[] { "host/appservice.corp.identityintervention.com" }
                        ),
                        saltType: SaltType.ActiveDirectoryUser
                    )
                )
            );

            var validated = (KerberosIdentity)await authenticator.Authenticate(encoded);

            Assert.IsNotNull(validated);

            Assert.AreEqual(validated.FindFirst(ClaimTypes.Sid).Value, "S-1-5-123-456-789-12-321-888");
        }

        private static async Task<IRealmService> LocateRealm(string realm, bool slow = false)
        {
            IRealmService service = new FakeRealmService(realm);

            if (slow)
            {
                await Task.Delay(500);
            }

            return service;
        }

        private class ExceptionTraceLog : ILogger
        {
            private readonly ConcurrentBag<Exception> exceptions = new ConcurrentBag<Exception>();

            public IEnumerable<Exception> Exceptions => exceptions;

            public LogLevel Level { get; set; } = LogLevel.Verbose;
            public bool Enabled { get; set; } = true;

            public void WriteLine(KerberosLogSource source, string value)
            {

            }

            public void WriteLine(KerberosLogSource source, Exception ex)
            {
                WriteLine(source, "", ex);
            }

            public void WriteLine(KerberosLogSource source, string value, Exception ex)
            {
                exceptions.Add(ex);
            }
        }

        private class FakeRealmService : IRealmService
        {
            private readonly string realm;

            public FakeRealmService(string realm)
            {
                this.realm = realm;
            }

            public IRealmSettings Settings => new FakeRealmSettings();

            public IPrincipalService Principals => new FakePrincipalService(realm);

            public string Name => realm;

            public DateTimeOffset Now()
            {
                return DateTimeOffset.UtcNow;
            }
        }

        internal class FakePrincipalService : IPrincipalService
        {
            private string realm;

            public FakePrincipalService(string realm)
            {
                this.realm = realm;
            }

            public Task<IKerberosPrincipal> Find(string principalName)
            {
                IKerberosPrincipal principal = new FakeKerberosPrincipal(principalName);

                return Task.FromResult(principal);
            }

            public Task<IKerberosPrincipal> RetrieveKrbtgt()
            {
                IKerberosPrincipal krbtgt = new FakeKerberosPrincipal("krbtgt");

                return Task.FromResult(krbtgt);
            }
        }

        internal class FakeKerberosPrincipal : IKerberosPrincipal
        {
            private static readonly byte[] KrbTgtKey = new byte[] {
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0
            };

            private static readonly SecurityIdentifier domainSid = new SecurityIdentifier(IdentifierAuthority.NTAuthority, new int[] {
                123,456,789,012,321
            }, 0);

            private readonly SecurityIdentifier userSid = new SecurityIdentifier(
                IdentifierAuthority.NTAuthority,
                domainSid.SubAuthorities.Concat(new[] { 888 }).ToArray(),
                0
            );

            private readonly SecurityIdentifier groupSid = new SecurityIdentifier(
                IdentifierAuthority.NTAuthority,
                domainSid.SubAuthorities.Concat(new[] { 513 }).ToArray(),
                0
            );

            private readonly static byte[] FakePassword = Encoding.Unicode.GetBytes("P@ssw0rd!");

            private const string realm = "CORP.IDENTITYINTERVENTION.COM";

            public FakeKerberosPrincipal(string principalName)
            {
                PrincipalName = principalName;
                Expires = DateTimeOffset.UtcNow.AddMonths(9999);
            }

            public SupportedEncryptionTypes SupportedEncryptionTypes { get; set; }
                 = SupportedEncryptionTypes.Aes128CtsHmacSha196 |
                   SupportedEncryptionTypes.Aes256CtsHmacSha196 |
                   SupportedEncryptionTypes.Rc4Hmac |
                   SupportedEncryptionTypes.DesCbcCrc |
                   SupportedEncryptionTypes.DesCbcMd5;

            public IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; set; } = new[] { PaDataType.PA_ENC_TIMESTAMP };

            public string PrincipalName { get; set; }

            public DateTimeOffset? Expires { get; set; }

            public Task<PrivilegedAttributeCertificate> GeneratePac()
            {
                var pac = new PrivilegedAttributeCertificate()
                {
                    LogonInfo = new PacLogonInfo
                    {
                        DomainName = realm,
                        UserName = PrincipalName,
                        UserDisplayName = PrincipalName,
                        BadPasswordCount = 12,
                        SubAuthStatus = 0,
                        DomainSid = domainSid,
                        UserSid = userSid,
                        GroupSid = groupSid,
                        LogonTime = DateTimeOffset.UtcNow,
                        ServerName = "server"
                    }
                };

                return Task.FromResult(pac);
            }

            public Task<KerberosKey> RetrieveLongTermCredential()
            {
                KerberosKey key;

                if (PrincipalName == "krbtgt")
                {
                    key = new KerberosKey(
                        password: KrbTgtKey,
                        principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm, new[] { "krbtgt" }),
                        etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
                        saltType: SaltType.ActiveDirectoryUser
                    );
                }
                else
                {
                    key = new KerberosKey(
                        password: FakePassword,
                        principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm, new[] { PrincipalName }),
                        etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
                        saltType: SaltType.ActiveDirectoryUser
                    );
                }

                return Task.FromResult(key);
            }
        }

        internal class FakeRealmSettings : IRealmSettings
        {
            public TimeSpan MaximumSkew => TimeSpan.FromMinutes(5);

            public TimeSpan SessionLifetime => TimeSpan.FromHours(10);

            public TimeSpan MaximumRenewalWindow => TimeSpan.FromDays(7);
        }
    }
}
