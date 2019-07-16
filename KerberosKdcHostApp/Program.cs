using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace KerberosKdcHostApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            KdcServiceListener listener = new KdcServiceListener(new KdcListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, 8888),
                Log = new ConsoleLogger(),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            });

            await listener.Start();
        }

        private static Task<IRealmService> LocateRealm(string realm)
        {
            IRealmService service = new FakeRealmService(realm);

            return Task.FromResult(service);
        }
    }

    internal class FakeRealmService : IRealmService
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

        private readonly static byte[] FakePassword = Encoding.Unicode.GetBytes("P@ssw0rd!");

        private const string realm = "CORP.IDENTITYINTERVENTION.COM";

        public FakeKerberosPrincipal(string principalName)
        {
            PrincipalName = principalName;
        }

        public IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; set; } = new[] { PaDataType.PA_ENC_TIMESTAMP };

        public string PrincipalName { get; set; }

        public Task<PrivilegedAttributeCertificate> GeneratePac()
        {
            var pac = new PrivilegedAttributeCertificate();

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

        public TimeSpan SessionLifetime => TimeSpan.FromHours(12);

        public TimeSpan MaximumRenewalWindow => TimeSpan.FromDays(14);
    }

    internal class ConsoleLogger : ILogger
    {
        public LogLevel Level { get; set; } = LogLevel.Debug;

        public bool Enabled { get; set; } = true;

        public void WriteLine(KerberosLogSource source, string value)
        {
            if (!Enabled)
            {
                return;
            }

            Console.WriteLine($"[{source}] {value}");
        }

        public void WriteLine(KerberosLogSource source, string value, Exception ex)
        {
            if (!Enabled)
            {
                return;
            }

            Console.WriteLine($"[{source}] {value}");

            WriteLine(source, ex);
        }

        public void WriteLine(KerberosLogSource source, Exception ex)
        {
            if (!Enabled)
            {
                return;
            }

            var exValue = new StringBuilder();

            if (ex is AggregateException agg)
            {
                for (var i = 0; i < agg.InnerExceptions.Count; i++)
                {
                    exValue.AppendFormat($"\r\n[{source}]\t[{i}] {agg.InnerExceptions[i]}");
                }
            }
            else
            {
                exValue.AppendFormat($"\r\n[{source}] {ex}");
            }

            Console.WriteLine(exValue);
        }
    }
}
