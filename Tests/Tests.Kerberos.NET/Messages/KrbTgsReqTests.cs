// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Linq;
using System.Security;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KrbTgsReqTests : BaseTest
    {
        private static readonly byte[] Key = new byte[]
        {
            0xef, 0x74, 0x22, 0xcb, 0x49, 0xe2, 0xf5, 0xb0, 0x92, 0x92, 0xcb, 0xd8, 0x25, 0xc2, 0x95, 0x24,
            0x9f, 0x2a, 0x31, 0x46, 0x5d, 0xc9, 0xab, 0x4a, 0x30, 0x80, 0xed, 0xf3, 0x16, 0x8a, 0x88, 0x57
        };

        [TestMethod]
        public void TgsParse()
        {
            var tgsReqBytes = ReadDataFile("messages\\tgs-req-testuser-host-app03").Skip(4).ToArray();

            var tgsReq = KrbTgsReq.DecodeApplication(tgsReqBytes);

            KrbEncTicketPart krbtgt = ExtractTgt(tgsReq);

            Assert.AreEqual("testuser", krbtgt.CName.FullyQualifiedName);
        }

        [TestMethod]
        public void ValidateS4uSelf()
        {
            RetrieveS4u(out KrbTgsReq tgsReq, out KrbEncTicketPart krbtgt);

            var sessionKey = krbtgt.Key;

            var paForUserPaData = tgsReq.PaData.FirstOrDefault(pa => pa.Type == PaDataType.PA_FOR_USER);

            Assert.IsNotNull(paForUserPaData);

            var paForUser = KrbPaForUser.Decode(paForUserPaData.Value);

            paForUser.ValidateChecksum(sessionKey.AsKey());
        }

        [TestMethod]
        public void ValidateS4uSelfPacOptions()
        {
            RetrieveS4u(out KrbTgsReq tgsReq, out KrbEncTicketPart krbtgt);

            var paPacOptions = tgsReq.PaData.FirstOrDefault(pa => pa.Type == PaDataType.PA_PAC_OPTIONS);

            Assert.IsNotNull(paPacOptions);

            var pacOptions = KrbPaPacOptions.Decode(paPacOptions.Value);

            Assert.AreEqual(PacOptions.BranchAware | PacOptions.Claims | PacOptions.ResourceBasedConstrainedDelegation, pacOptions.Flags);
        }

        private static void RetrieveS4u(out KrbTgsReq tgsReq, out KrbEncTicketPart krbtgt)
        {
            var tgsReqBytes = ReadDataFile("messages\\tgs-req-app2-s4u-self").Skip(4).ToArray();

            tgsReq = KrbTgsReq.DecodeApplication(tgsReqBytes);
            Assert.IsNotNull(tgsReq);

            krbtgt = ExtractTgt(tgsReq);
            Assert.IsNotNull(krbtgt);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void ValidateS4uSelf_Modified()
        {
            RetrieveS4u(out KrbTgsReq tgsReq, out KrbEncTicketPart krbtgt);

            var sessionKey = krbtgt.Key;

            var paForUserPaData = tgsReq.PaData.FirstOrDefault(pa => pa.Type == PaDataType.PA_FOR_USER);

            Assert.IsNotNull(paForUserPaData);

            var paForUser = KrbPaForUser.Decode(paForUserPaData.Value);

            paForUser.UserName = KrbPrincipalName.FromString("administrator@test.com");

            paForUser.ValidateChecksum(sessionKey.AsKey());
        }

        private static KrbEncTicketPart ExtractTgt(KrbTgsReq tgsReq)
        {
            var paData = tgsReq.PaData.First(p => p.Type == PaDataType.PA_TGS_REQ);

            var apReq = paData.DecodeApReq();

            var krbtgtKey = new KerberosKey(key: Key, etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);

            return apReq.Ticket.EncryptedPart.Decrypt(krbtgtKey, KeyUsage.Ticket, b => new KrbEncTicketPart().DecodeAsApplication(b));
        }
    }
}