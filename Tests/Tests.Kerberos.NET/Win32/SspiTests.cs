using Kerberos.NET;
using Kerberos.NET.Entities;
using Kerberos.NET.Win32;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Tests.Kerberos.NET.Win32
{
    [TestClass]
    public class SspiTests
    {
        [TestMethod]
        public void TryGettingSspiTicketTest()
        {
            using (var contextSender = new SspiContext($"host/{Environment.MachineName}", "Negotiate"))
            using (var contextReceiver = new SspiContext($"host/{Environment.MachineName}", "Negotiate"))
            {
                var token = contextSender.RequestToken();

                Assert.IsNotNull(token);

                var contextToken = MessageParser.Parse<NegotiateContextToken>(token);

                Assert.IsNotNull(contextToken);

                contextReceiver.AcceptToken(token, out byte[] serverResponse);

                Assert.IsNotNull(serverResponse);

                var serverContext = NegotiationToken.Decode(serverResponse);

                Assert.IsNotNull(serverContext);
                Assert.IsNotNull(serverContext.ResponseToken);
                Assert.IsNull(serverContext.InitialToken);
            }
        }
    }
}
