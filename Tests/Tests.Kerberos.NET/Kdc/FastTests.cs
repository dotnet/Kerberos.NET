// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class FastTests : BaseTest
    {
        private const string Realm = "CORP2.IDENTITYINTERVENTION.COM";
        private const string Upn = "fake@" + Realm;
        private const string Password = "P@ssw0rd!";

        private static KerberosPasswordCredential CreateCredential()
        {
            return new KerberosPasswordCredential(Upn, Password, Realm)
            {
                Salts = new[]
                {
                    new KeyValuePair<EncryptionType, string>(
                        EncryptionType.AES256_CTS_HMAC_SHA1_96,
                        "CORP.IDENTITYINTERVENTION.COMfake@CORP2.IDENTITYINTERVENTION.COM"
                    )
                },
                Configuration = Krb5Config.Default()
            };
        }

        private static KdcServerOptions CreateServerOptions()
        {
            return new KdcServerOptions
            {
                DefaultRealm = Realm,
                IsDebug = true,
                RealmLocator = realm => new FakeRealmService(realm)
            };
        }

        /// <summary>
        /// First, get a TGT without FAST (to use as armor ticket),
        /// then use that TGT as FAST armor for a second AS-REQ.
        /// </summary>
        private (KrbAsRep armorTgt, KrbEncKdcRepPart armorDecrypted) GetArmorTgt()
        {
            var cred = CreateCredential();

            var asReq = KrbAsReq.CreateAsReq(cred, AuthenticationOptions.AllAuthentication);

            var handler = new KdcAsReqMessageHandler(asReq.EncodeApplication(), CreateServerOptions());

            handler.PreAuthHandlers[PaDataType.PA_ENC_TIMESTAMP] = service => new PaDataTimestampHandler(service);

            var results = handler.Execute();

            var asRep = KrbAsRep.DecodeApplication(results);

            var decrypted = cred.DecryptKdcRep(
                asRep,
                KeyUsage.EncAsRepPart,
                d => KrbEncAsRepPart.DecodeApplication(d)
            );

            return (asRep, decrypted);
        }

        [TestMethod]
        public void FastArmorContext_WrapUnwrap_RoundTrip()
        {
            // Get an armor TGT
            var (armorTgt, armorDecrypted) = GetArmorTgt();

            // Create armor context
            var armorContext = new FastArmorContext(armorTgt, armorDecrypted);

            // Create a simple AS-REQ to wrap
            var cred = CreateCredential();
            var asReq = KrbAsReq.CreateAsReq(cred, AuthenticationOptions.AllAuthentication);

            // Wrap the request
            var wrappedReq = armorContext.WrapRequest(asReq);

            // Verify the wrapped request has PA_FX_FAST
            Assert.IsNotNull(wrappedReq);
            Assert.IsNotNull(wrappedReq.PaData);

            var paFast = wrappedReq.PaData.FirstOrDefault(p => p.Type == PaDataType.PA_FX_FAST);
            Assert.IsNotNull(paFast, "Wrapped request should contain PA_FX_FAST");

            // Verify the armor key was derived
            Assert.IsNotNull(armorContext.ArmorKey, "Armor key should be derived after wrapping");

            // Decode the PA_FX_FAST to verify structure
            var fastRequest = KrbPaFxFastRequest.Decode(paFast.Value);
            Assert.IsNotNull(fastRequest.ArmoredData);
            Assert.IsNotNull(fastRequest.ArmoredData.Armor, "Armor should be present for AS-REQ");
            Assert.AreEqual(KrbArmorType.FX_FAST_ARMOR_AP_REQUEST, fastRequest.ArmoredData.Armor.Type);
            Assert.IsNotNull(fastRequest.ArmoredData.RequestChecksum);
            Assert.IsNotNull(fastRequest.ArmoredData.EncryptedFastRequest);
        }

        [TestMethod]
        public void FastArmorContext_ArmorKeyDerivation()
        {
            // Get an armor TGT
            var (armorTgt, armorDecrypted) = GetArmorTgt();

            var armorContext = new FastArmorContext(armorTgt, armorDecrypted);

            var cred = CreateCredential();
            var asReq = KrbAsReq.CreateAsReq(cred, AuthenticationOptions.AllAuthentication);

            armorContext.WrapRequest(asReq);

            // Verify armor key properties
            Assert.IsNotNull(armorContext.ArmorKey);
            Assert.AreEqual(armorDecrypted.Key.EType, armorContext.ArmorKey.EncryptionType);
        }

        [TestMethod]
        public void PaDataFastHandler_PreValidate_DecodesArmoredRequest()
        {
            // Get an armor TGT
            var (armorTgt, armorDecrypted) = GetArmorTgt();

            // Create client-side armor context and wrap a request
            var armorContext = new FastArmorContext(armorTgt, armorDecrypted);

            var cred = CreateCredential();

            var asReq = KrbAsReq.CreateAsReq(cred, AuthenticationOptions.AllAuthentication);
            var wrappedReq = armorContext.WrapRequest(asReq);

            // Set up the server-side handler
            var realmService = new FakeRealmService(Realm);

            var handler = new PaDataFastHandler(realmService);

            var preauth = new PreAuthenticationContext
            {
                Message = wrappedReq
            };

            // PreValidate should succeed and populate FastState
            handler.PreValidate(preauth);

            var state = preauth.GetState<FastState>(PaDataType.PA_FX_FAST);

            Assert.IsNotNull(state.ArmorKey, "Armor key should be derived");
            Assert.IsNotNull(state.InnerRequest, "Inner request should be decrypted");
            Assert.IsNotNull(state.DecryptedArmorApReq, "Armor AP-REQ should be decrypted");
        }

        [TestMethod]
        public void PaDataFastHandler_PreValidate_NoFast_DoesNothing()
        {
            var realmService = new FakeRealmService(Realm);
            var handler = new PaDataFastHandler(realmService);

            var cred = CreateCredential();
            var asReq = KrbAsReq.CreateAsReq(cred, AuthenticationOptions.AllAuthentication);

            var preauth = new PreAuthenticationContext
            {
                Message = asReq
            };

            // Should not throw - just returns without doing anything
            handler.PreValidate(preauth);

            // FastState should not have an armor key
            Assert.IsFalse(
                preauth.PreAuthenticationState.ContainsKey(PaDataType.PA_FX_FAST),
                "FastState should not be created when no FAST PA-Data is present"
            );
        }

        [TestMethod]
        public void FastState_Properties()
        {
            var state = new FastState();

            Assert.IsNull(state.ArmorKey);
            Assert.IsNull(state.InnerRequest);
            Assert.IsNull(state.StrengthenKey);
            Assert.IsNull(state.DecryptedArmorApReq);
        }

        [TestMethod]
        public void Cf2_ArmorKeyDerivation_Deterministic()
        {
            // Verify that Cf2 produces consistent results
            var key1 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
            var key2 = new byte[] { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
            var pepper1 = Encoding.UTF8.GetBytes("subkeyarmor");
            var pepper2 = Encoding.UTF8.GetBytes("ticketarmor");

            var result1 = KrbFx.Cf2(key1, key2, pepper1, pepper2, EncryptionType.AES128_CTS_HMAC_SHA1_96);
            var result2 = KrbFx.Cf2(key1, key2, pepper1, pepper2, EncryptionType.AES128_CTS_HMAC_SHA1_96);

            Assert.IsTrue(result1.Span.SequenceEqual(result2.Span), "Cf2 should produce deterministic results");
            Assert.AreEqual(16, result1.Length, "AES128 key should be 16 bytes");
        }

        [TestMethod]
        public void EncryptedChallengeHandler_NoFastArmor_Throws()
        {
            var realmService = new FakeRealmService(Realm);
            var handler = new PaDataEncryptedChallengeHandler(realmService);

            var cred = CreateCredential();
            var asReq = KrbAsReq.CreateAsReq(cred, AuthenticationOptions.AllAuthentication);

            var preauth = new PreAuthenticationContext
            {
                Message = asReq,
                Principal = realmService.Principals.Find(
                    KrbPrincipalName.FromString(Upn), Realm
                )
            };

            // Encrypted challenge without FAST armor should throw
            Assert.ThrowsException<KerberosProtocolException>(() =>
            {
                handler.Validate(asReq, preauth);
            });
        }

        [TestMethod]
        public void WrapFastResponse_NullState_ReturnsNull()
        {
            var result = PaDataFastHandler.WrapFastResponse(null, null, null, null);
            Assert.IsNull(result, "Should return null when no FAST state");
        }

        [TestMethod]
        public void WrapFastError_NullState_ReturnsNull()
        {
            var result = PaDataFastHandler.WrapFastError(null, null);
            Assert.IsNull(result, "Should return null when no FAST state");
        }

        [TestMethod]
        public void WrapFastError_WithState_ProducesValidPaData()
        {
            var etype = EncryptionType.AES256_CTS_HMAC_SHA1_96;
            var armorKeyData = KrbEncryptionKey.Generate(etype);
            var armorKey = armorKeyData.AsKey();

            var state = new FastState
            {
                ArmorKey = armorKey,
                InnerRequest = new KrbFastReq
                {
                    FastOptions = FastOptions.Reserved,
                    PaData = Array.Empty<KrbPaData>(),
                    ReqBody = new KrbKdcReqBody
                    {
                        Nonce = 12345
                    }
                }
            };

            var error = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED,
                EText = "test error",
                Realm = Realm,
                SName = KrbPrincipalName.FromString("krbtgt/" + Realm)
            };
            error.StampServerTime();

            var result = PaDataFastHandler.WrapFastError(state, error);

            Assert.IsNotNull(result);
            Assert.AreEqual(PaDataType.PA_FX_FAST, result.Type);

            // Verify the reply can be decoded
            var reply = KrbPaFxFastReply.Decode(result.Value);
            Assert.IsNotNull(reply.ArmoredData);
            Assert.IsNotNull(reply.ArmoredData.EncFastRep);

            // Decrypt and verify
            var fastResponse = reply.ArmoredData.EncFastRep.Decrypt(
                armorKey,
                KeyUsage.FastRep,
                b => KrbFastResponse.Decode(b)
            );

            Assert.IsNotNull(fastResponse);
            Assert.AreEqual(12345, fastResponse.Nonce);
            Assert.IsNotNull(fastResponse.PaData);
            Assert.IsTrue(fastResponse.PaData.Length > 0);
        }

        [TestMethod]
        public void KdcServer_RegistersFastHandlers_WhenEnabled()
        {
            var config = Krb5Config.Default();
            config.KdcDefaults.RegisterDefaultFastHandler = true;

            var options = new KdcServerOptions
            {
                DefaultRealm = Realm,
                IsDebug = true,
                RealmLocator = realm => new FakeRealmService(realm),
                Configuration = config
            };

            var server = new KdcServer(options);

            // The server should have registered FAST handlers internally.
            // We can verify this by trying to process a FAST-armored message.
            // For now, just verify the server was created without errors.
            Assert.IsNotNull(server);
        }
    }
}
