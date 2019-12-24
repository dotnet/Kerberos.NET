using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Buffers;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KdcServerTests
    {
        [TestMethod]
        public async Task KdcTagPeekFailureApplication()
        {
            var kdc = new KdcServer(new ListenerOptions { DefaultRealm = "domain.com", IsDebug = true, Log = new FakeExceptionLoggerFactory() });

            var checksum = new KrbChecksum { };

            ReadOnlySequence<byte> request = new ReadOnlySequence<byte>(checksum.Encode().ToArray());

            var response = await kdc.ProcessMessage(request);

            var err = KrbError.DecodeApplication(response);

            Assert.IsNotNull(err);

            Assert.AreEqual(KerberosErrorCode.KRB_ERR_GENERIC, err.ErrorCode);
        }

        [TestMethod]
        public async Task KdcTagPeekFailureUnknownHandler()
        {
            var kdc = new KdcServer(new ListenerOptions { DefaultRealm = "domain.com", IsDebug = true });

            var aprepPart = new KrbEncApRepPart { };

            ReadOnlySequence<byte> request = new ReadOnlySequence<byte>(aprepPart.EncodeApplication().ToArray());

            var response = await kdc.ProcessMessage(request);

            var err = KrbError.DecodeApplication(response);

            Assert.IsNotNull(err);

            Assert.AreEqual(KerberosErrorCode.KRB_ERR_GENERIC, err.ErrorCode);
            Assert.IsTrue(err.EText.Contains("doesn't have a message handler registered"));
        }

        [TestMethod]
        public async Task KdcTagPeekFailureNullBuilder()
        {
            var kdc = new KdcServer(new ListenerOptions { DefaultRealm = "domain.com", IsDebug = true });
            kdc.RegisterMessageHandler((MessageType)27, (b, o) => null);

            var aprepPart = new KrbEncApRepPart { };

            ReadOnlySequence<byte> request = new ReadOnlySequence<byte>(aprepPart.EncodeApplication().ToArray());

            var response = await kdc.ProcessMessage(request);

            var err = KrbError.DecodeApplication(response);

            Assert.IsNotNull(err);

            Assert.AreEqual(KerberosErrorCode.KRB_ERR_GENERIC, err.ErrorCode);
            Assert.IsTrue(err.EText.Contains("Message handler builder 27 must not return null"));
        }

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public void RegisterHandlerInvalidHigh()
        {
            var kdc = new KdcServer(new ListenerOptions { });

            kdc.RegisterMessageHandler((MessageType)123, null);
        }

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public void RegisterHandlerInvalidLow()
        {
            var kdc = new KdcServer(new ListenerOptions { });

            kdc.RegisterMessageHandler((MessageType)9, null);
        }

        [TestMethod]
        public async Task ParseKdcProxyMessage()
        {
            var req = KrbAsReq.CreateAsReq(
                new KerberosPasswordCredential("blah@corp.identityintervention.com", "P@ssw0rd!"),
                0
            ).EncodeApplication();

            var domain = "corp.identityintervention.com";
            var hint = DcLocatorHint.DS_AVOID_SELF;

            var messageBytes = new Memory<byte>(new byte[req.Length + 4]);

            Endian.ConvertToBigEndian(req.Length, messageBytes.Slice(0, 4));
            req.CopyTo(messageBytes.Slice(4, req.Length));

            var message = new KdcProxyMessage
            {
                TargetDomain = domain,
                KerbMessage = messageBytes,
                DcLocatorHint = hint
            };

            var kdc = new KdcServer(new ListenerOptions { RealmLocator = LocateFakeRealm });

            var response = await kdc.ProcessMessage(new ReadOnlySequence<byte>(message.Encode()));

            Assert.IsTrue(response.Length > 0);
            Assert.IsFalse(KrbError.CanDecode(response));

            var proxy = KdcProxyMessage.Decode(response);

            var preAuthReq = KrbError.DecodeApplication(proxy.KerbMessage);

            Assert.AreEqual(KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED, preAuthReq.ErrorCode);
        }

        private static Task<IRealmService> LocateFakeRealm(string realm)
        {
            IRealmService service = new FakeRealmService(realm);

            return Task.FromResult(service);
        }
    }
}
