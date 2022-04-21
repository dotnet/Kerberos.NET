// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Globalization;
using System.Linq;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KrbtgtTests : BaseTest
    {
        private const string Realm = "corp.test.internal";
        private const string UpperCaseRealm = "CORP.TEST.INTERNAL";
        private const string KrbtgtSpn = "krbtgt/" + Realm;
        private const string UserUpn = "user@test.internal";
        private const string TestSamAccountName = "SamAccount";

        private const TicketFlags ExpectedFlags = TicketFlags.EncryptedPreAuthentication | TicketFlags.Renewable | TicketFlags.Forwardable;

        internal static readonly byte[] FakeKey = new byte[]
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };

        private static readonly byte[] TgtKey = FakeKey;

        private static readonly byte[] Key = new byte[]
        {
            0xef, 0x74, 0x22, 0xcb, 0x49, 0xe2, 0xf5, 0xb0, 0x92, 0x92, 0xcb, 0xd8, 0x25, 0xc2, 0x95, 0x24,
            0x9f, 0x2a, 0x31, 0x46, 0x5d, 0xc9, 0xab, 0x4a, 0x30, 0x80, 0xed, 0xf3, 0x16, 0x8a, 0x88, 0x57
        };

        [TestMethod]
        public void KrbtgtDecode()
        {
            var krbtgtKey = new KerberosKey(key: Key, etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);
            var longUserTermKey = new KerberosKey("P@ssw0rd!", salt: "CORP.IDENTITYINTERVENTION.COMtestuser");

            var krbAsRepBytes = ReadDataFile("messages\\as-rep").Skip(4).ToArray();

            var asRep = new KrbAsRep().DecodeAsApplication(krbAsRepBytes);

            var encPart = asRep.EncPart.Decrypt(longUserTermKey, KeyUsage.EncAsRepPart, b => KrbEncAsRepPart.DecodeApplication(b));

            Assert.IsNotNull(encPart);

            var encTicket = asRep.Ticket.EncryptedPart;

            var krbtgt = encTicket.Decrypt(krbtgtKey, KeyUsage.Ticket, bytes => new KrbEncTicketPart().DecodeAsApplication(bytes));

            Assert.IsNotNull(krbtgt);
        }

        [DataTestMethod]
        [DataRow(Realm, KerberosCompatibilityFlags.None, Realm)]
        [DataRow(Realm, KerberosCompatibilityFlags.NormalizeRealmsUppercase, UpperCaseRealm)]
        [DataRow(UpperCaseRealm, KerberosCompatibilityFlags.None, UpperCaseRealm)]
        [DataRow(UpperCaseRealm, KerberosCompatibilityFlags.NormalizeRealmsUppercase, UpperCaseRealm)]
        public void GeneratedTgtMatchesActiveDirectory(string realm, KerberosCompatibilityFlags compatibilityFlags, string expectedRealm)
        {
            var realmService = new FakeRealmService(realm, compatibilityFlags: compatibilityFlags);
            var principal = realmService.Principals.Find(KrbPrincipalName.FromString(UserUpn));

            var principalKey = principal.RetrieveLongTermCredential();

            var rst = new ServiceTicketRequest
            {
                Flags = ExpectedFlags,
                Principal = principal,
                EncryptedPartKey = principalKey,
                ServicePrincipalKey = new KerberosKey(key: TgtKey, etype: EncryptionType.AES256_CTS_HMAC_SHA1_96)
            };

            var tgt = KrbAsRep.GenerateTgt(rst, realmService);

            Assert.IsNotNull(tgt);

            var encoded = tgt.EncodeApplication();

            AssertIsExpectedKrbtgt(principalKey, rst.ServicePrincipalKey, encoded.ToArray(), expectedRealm);
        }

        private static void AssertIsExpectedKrbtgt(KerberosKey clientKey, KerberosKey tgtKey, byte[] message, string expectedRealm)
        {
            var asRep = new KrbAsRep().DecodeAsApplication(message);

            Assert.IsNotNull(asRep);

            var encPart = asRep.EncPart.Decrypt(
                clientKey,
                KeyUsage.EncAsRepPart,
                b => KrbEncAsRepPart.DecodeApplication(b)
            );

            Assert.IsNotNull(encPart);

            Assert.AreEqual(KrbtgtSpn, encPart.SName.FullyQualifiedName, true, CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedRealm, encPart.Realm);

            Assert.IsNotNull(encPart.Key);

            Assert.AreEqual(ExpectedFlags, encPart.Flags);

            var krbtgt = asRep.Ticket.EncryptedPart.Decrypt(
                tgtKey,
                KeyUsage.Ticket,
                d => new KrbEncTicketPart().DecodeAsApplication(d)
            );

            Assert.IsNotNull(krbtgt);

            Assert.AreEqual(krbtgt.CName.FullyQualifiedName, asRep.CName.FullyQualifiedName);

            Assert.AreEqual(UserUpn, krbtgt.CName.FullyQualifiedName, true, CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedRealm, krbtgt.CRealm);
            Assert.AreEqual(ExpectedFlags, krbtgt.Flags);

            Assert.IsTrue(Enumerable.SequenceEqual(krbtgt.Key.KeyValue.ToArray(), encPart.Key.KeyValue.ToArray()));
        }

        [DataTestMethod]
        [DataRow(Realm, KerberosCompatibilityFlags.None, Realm)]
        [DataRow(Realm, KerberosCompatibilityFlags.NormalizeRealmsUppercase, UpperCaseRealm)]
        [DataRow(UpperCaseRealm, KerberosCompatibilityFlags.None, UpperCaseRealm)]
        [DataRow(UpperCaseRealm, KerberosCompatibilityFlags.NormalizeRealmsUppercase, UpperCaseRealm)]
        public void GeneratedTgtMatchesWithOnPremisesSamAccountName(string realm, KerberosCompatibilityFlags compatibilityFlags, string expectedRealm)
        {
            var realmService = new FakeRealmService(realm, compatibilityFlags: compatibilityFlags);
            var principal = realmService.Principals.Find(KrbPrincipalName.FromString(UserUpn));

            var principalKey = principal.RetrieveLongTermCredential();

            var rst = new ServiceTicketRequest
            {
                SamAccountName = TestSamAccountName,
                Flags = ExpectedFlags,
                Principal = principal,
                EncryptedPartKey = principalKey,
                ServicePrincipalKey = new KerberosKey(key: TgtKey, etype: EncryptionType.AES256_CTS_HMAC_SHA1_96)
            };

            var tgt = KrbAsRep.GenerateTgt(rst, realmService);

            Assert.IsNotNull(tgt);

            var encoded = tgt.EncodeApplication();

            AssertIsExpectedKrbtgtWithOnPremisesSamAccountName(principalKey, rst.ServicePrincipalKey, encoded.ToArray(), expectedRealm);
        }

        private static void AssertIsExpectedKrbtgtWithOnPremisesSamAccountName(KerberosKey clientKey, KerberosKey tgtKey, byte[] message, string expectedRealm)
        {
            var asRep = new KrbAsRep().DecodeAsApplication(message);

            Assert.IsNotNull(asRep);

            // CName under reply part should NOT be original UPN
            Assert.AreNotEqual(UserUpn, asRep.CName.FullyQualifiedName);
            Assert.AreEqual(TestSamAccountName, asRep.CName.FullyQualifiedName);

            var encPart = asRep.EncPart.Decrypt(
                clientKey,
                KeyUsage.EncAsRepPart,
                b => KrbEncAsRepPart.DecodeApplication(b)
            );

            Assert.IsNotNull(encPart);

            Assert.AreEqual(KrbtgtSpn, encPart.SName.FullyQualifiedName, true, CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedRealm, encPart.Realm);

            Assert.IsNotNull(encPart.Key);

            Assert.AreEqual(ExpectedFlags, encPart.Flags);

            var krbtgt = asRep.Ticket.EncryptedPart.Decrypt(
                tgtKey,
                KeyUsage.Ticket,
                d => new KrbEncTicketPart().DecodeAsApplication(d)
            );

            Assert.IsNotNull(krbtgt);

            // CName under encrypted ticket part should be matched with OnPremisesSamAccountName
            Assert.IsTrue(krbtgt.CName.Type == PrincipalNameType.NT_PRINCIPAL);
            Assert.IsTrue(krbtgt.CName.Name.Length == 1);
            Assert.AreEqual(TestSamAccountName, krbtgt.CName.FullyQualifiedName);

            Assert.AreEqual(expectedRealm, krbtgt.CRealm);
            Assert.AreEqual(ExpectedFlags, krbtgt.Flags);

            Assert.IsTrue(Enumerable.SequenceEqual(krbtgt.Key.KeyValue.ToArray(), encPart.Key.KeyValue.ToArray()));
        }
    }
}
