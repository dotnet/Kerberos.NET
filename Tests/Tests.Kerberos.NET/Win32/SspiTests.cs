// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Win32;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class SspiTests
    {
#if WINDOWS
        [TestMethod]
        public void TryGettingSspiTicketTest()
        {
            using (var contextSender = new SspiContext($"host/{Environment.MachineName}", "negotiate"))
            using (var contextReceiver = new SspiContext($"host/{Environment.MachineName}", "negotiate"))
            {
                byte[] token = null;
                byte[] serverResponse = null;

                do
                {
                    token = contextSender.RequestToken(serverResponse);

                    Assert.IsNotNull(token);

                    if (token != null && token.Length > 0)
                    {
                        contextReceiver.AcceptToken(token, out serverResponse);
                        Assert.IsNotNull(serverResponse);
                    }
                }
                while (token != null && token.Length > 0);

                var serverContext = NegotiationToken.Decode(serverResponse);

                Assert.IsNotNull(serverContext);
                Assert.IsNotNull(serverContext.ResponseToken);
                Assert.IsNull(serverContext.InitialToken);

                Assert.IsNotNull(contextSender.SessionKey);

                Assert.IsTrue(KerberosCryptoTransformer.AreEqualSlow(contextSender.SessionKey, contextReceiver.SessionKey));
            }
        }
#endif
    }
}
