using System;
using System.Threading.Tasks;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;

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

            var response = await kdc.ProcessMessage(checksum.Encode());

            var err = KrbError.DecodeApplication(response);

            Assert.IsNotNull(err);

            Assert.AreEqual(KerberosErrorCode.KRB_ERR_GENERIC, err.ErrorCode);
        }

        [TestMethod]
        public async Task KdcTagPeekFailureUnknownHandler()
        {
            var kdc = new KdcServer(new ListenerOptions { DefaultRealm = "domain.com", IsDebug = true });

            var krbCred = new KrbCred { Tickets = new KrbTicket[0] };

            var response = await kdc.ProcessMessage(krbCred.EncodeApplication());

            var err = KrbError.DecodeApplication(response);

            Assert.IsNotNull(err);

            Assert.AreEqual(KerberosErrorCode.KRB_ERR_GENERIC, err.ErrorCode);
            Assert.IsTrue(err.EText.Contains("doesn't have a message handler registered"));
        }

        [TestMethod]
        public async Task KdcTagPeekFailureNullBuilder()
        {
            var kdc = new KdcServer(new ListenerOptions { DefaultRealm = "domain.com", IsDebug = true });
            kdc.RegisterMessageHandler(MessageType.KRB_CRED, (b, o) => null);

            var krbCred = new KrbCred { Tickets = new KrbTicket[0] };

            var response = await kdc.ProcessMessage(krbCred.EncodeApplication());

            var err = KrbError.DecodeApplication(response);

            Assert.IsNotNull(err);

            Assert.AreEqual(KerberosErrorCode.KRB_ERR_GENERIC, err.ErrorCode);
            Assert.IsTrue(err.EText.Contains("Message handler builder KRB_CRED must not return null"));
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

            var message = KdcProxyMessage.WrapMessage(req, domain, hint, mode: KdcProxyMessageMode.IncludeLengthPrefix);

            var kdc = new KdcServer(new ListenerOptions { RealmLocator = realm => new FakeRealmService(realm) });

            var response = await kdc.ProcessMessage(message.Encode());

            Assert.IsTrue(response.Length > 0);
            Assert.IsFalse(KrbError.CanDecode(response));

            var proxy = KdcProxyMessage.Decode(response);

            var preAuthReq = KrbError.DecodeApplication(proxy.UnwrapMessage(out KdcProxyMessageMode mode));

            Assert.AreEqual(KdcProxyMessageMode.IncludeLengthPrefix, mode);

            Assert.AreEqual(KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED, preAuthReq.ErrorCode);
        }

        [TestMethod]
        public async Task ParseKdcProxyMessage_WithoutLength()
        {
            var req = KrbAsReq.CreateAsReq(
                new KerberosPasswordCredential("blah@corp.identityintervention.com", "P@ssw0rd!"),
                0
            ).EncodeApplication();

            var domain = "corp.identityintervention.com";
            var hint = DcLocatorHint.DS_AVOID_SELF;

            var message = KdcProxyMessage.WrapMessage(req, domain, hint, mode: KdcProxyMessageMode.NoPrefix);

            var kdc = new KdcServer(new ListenerOptions { RealmLocator = realm => new FakeRealmService(realm) });

            var response = await kdc.ProcessMessage(message.Encode());

            Assert.IsTrue(response.Length > 0);
            Assert.IsFalse(KrbError.CanDecode(response));

            var proxy = KdcProxyMessage.Decode(response);

            var preAuthReq = KrbError.DecodeApplication(proxy.UnwrapMessage(out KdcProxyMessageMode mode));

            Assert.AreEqual(KdcProxyMessageMode.NoPrefix, mode);

            Assert.AreEqual(KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED, preAuthReq.ErrorCode);
        }
    }
}
