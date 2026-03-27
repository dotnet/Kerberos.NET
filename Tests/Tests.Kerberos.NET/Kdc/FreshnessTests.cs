// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class FreshnessTests : BaseTest
    {
        private const string Realm = "CORP.IDENTITYINTERVENTION.COM";

        private static FakeRealmService CreateRealmService()
        {
            return new FakeRealmService(Realm);
        }

        private static IKerberosPrincipal FindKrbtgt(FakeRealmService realmService)
        {
            return realmService.Principals.Find(
                KrbPrincipalName.WellKnown.Krbtgt(Realm),
                Realm
            );
        }

        [TestMethod]
        public void FreshnessHandler_PostValidate_AddsFreshnessToken()
        {
            var realmService = CreateRealmService();
            var handler = new PaDataFreshnessHandler(realmService);

            var principal = FindKrbtgt(realmService);
            var preAuthList = new List<KrbPaData>();

            handler.PostValidate(principal, preAuthList);

            Assert.IsTrue(preAuthList.Count > 0, "PostValidate should add a PA-Data entry");
            Assert.IsTrue(
                preAuthList.Any(p => p.Type == PaDataType.PA_AS_FRESHNESS),
                "PostValidate should add a PA_AS_FRESHNESS entry"
            );
        }

        [TestMethod]
        public void FreshnessHandler_PostValidate_NullPrincipal_Throws()
        {
            var realmService = CreateRealmService();
            var handler = new PaDataFreshnessHandler(realmService);

            var preAuthList = new List<KrbPaData>();

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                handler.PostValidate(null, preAuthList);
            });
        }

        [TestMethod]
        public void FreshnessHandler_PostValidate_NullList_Throws()
        {
            var realmService = CreateRealmService();
            var handler = new PaDataFreshnessHandler(realmService);

            var principal = FindKrbtgt(realmService);

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                handler.PostValidate(principal, null);
            });
        }

        [TestMethod]
        public void ValidateFreshnessToken_ValidToken_ReturnsTrue()
        {
            var realmService = CreateRealmService();
            var handler = new PaDataFreshnessHandler(realmService);

            var principal = FindKrbtgt(realmService);
            var preAuthList = new List<KrbPaData>();

            handler.PostValidate(principal, preAuthList);

            var freshnessToken = preAuthList.First(p => p.Type == PaDataType.PA_AS_FRESHNESS);

            var krbtgtPrincipal = FindKrbtgt(realmService);
            var kdcKey = krbtgtPrincipal.RetrieveLongTermCredential();

            var isValid = PaDataFreshnessHandler.ValidateFreshnessToken(
                freshnessToken.Value,
                kdcKey,
                TimeSpan.FromMinutes(5),
                DateTimeOffset.UtcNow
            );

            Assert.IsTrue(isValid, "A freshly generated token should be valid");
        }

        [TestMethod]
        public void ValidateFreshnessToken_ExpiredToken_ReturnsFalse()
        {
            var realmService = CreateRealmService();
            var handler = new PaDataFreshnessHandler(realmService);

            var principal = FindKrbtgt(realmService);
            var preAuthList = new List<KrbPaData>();

            handler.PostValidate(principal, preAuthList);

            var freshnessToken = preAuthList.First(p => p.Type == PaDataType.PA_AS_FRESHNESS);

            var krbtgtPrincipal = FindKrbtgt(realmService);
            var kdcKey = krbtgtPrincipal.RetrieveLongTermCredential();

            var isValid = PaDataFreshnessHandler.ValidateFreshnessToken(
                freshnessToken.Value,
                kdcKey,
                TimeSpan.FromMinutes(5),
                DateTimeOffset.UtcNow.AddHours(24)
            );

            Assert.IsFalse(isValid, "A token validated far in the future should be expired");
        }

        [TestMethod]
        public void ValidateFreshnessToken_WrongKey_ReturnsFalse()
        {
            var realmService = CreateRealmService();
            var handler = new PaDataFreshnessHandler(realmService);

            var principal = FindKrbtgt(realmService);
            var preAuthList = new List<KrbPaData>();

            handler.PostValidate(principal, preAuthList);

            var freshnessToken = preAuthList.First(p => p.Type == PaDataType.PA_AS_FRESHNESS);

            var wrongKeyData = KrbEncryptionKey.Generate(EncryptionType.AES256_CTS_HMAC_SHA1_96);
            var wrongKey = wrongKeyData.AsKey();

            var isValid = PaDataFreshnessHandler.ValidateFreshnessToken(
                freshnessToken.Value,
                wrongKey,
                TimeSpan.FromMinutes(5),
                DateTimeOffset.UtcNow
            );

            Assert.IsFalse(isValid, "Validation with a wrong key should fail");
        }

        [TestMethod]
        public void ValidateFreshnessToken_GarbageData_ReturnsFalse()
        {
            var wrongKeyData = KrbEncryptionKey.Generate(EncryptionType.AES256_CTS_HMAC_SHA1_96);
            var wrongKey = wrongKeyData.AsKey();

            var garbageData = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };

            var isValid = PaDataFreshnessHandler.ValidateFreshnessToken(
                garbageData,
                wrongKey,
                TimeSpan.FromMinutes(5),
                DateTimeOffset.UtcNow
            );

            Assert.IsFalse(isValid, "Garbage data should not validate");
        }
    }
}
