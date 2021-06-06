// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Globalization;
using System.Linq;
using System.Security;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class PacTests : BaseTest
    {
        private const string RC4PACSIGNATURE = "dv///9uwIJUdzAWaCdn16YcrrEk=";
        private const string
            RC4PAC = "BQAAAAAAAAABAAAAIAMAAFgAAAAAAAAACgAAABwAAAB4AwAAAAAAAAwAAABQAAAAmAMAAAAAAAAGAAAAFAAAAOgDAAAAAAAABwAA" +
                "ABQAAAAABAAAAAAAAAEQCADMzMzMEAMAAAAAAAAAAAIAYE1z2X1yyQH/////////f/////////9/sFbR+dRwyQGwFjsknnHJAf////////" +
                "9/EgASAAQAAgASABIACAACAAAAAAAMAAIAAAAAABAAAgAAAAAAFAACAAAAAAAYAAIALgAAAFIEAAABAgAACwAAABwAAgAgAAAAAAAAAAAA" +
                "AAAAAAAAAAAAAAwADgAgAAIADAAOACQAAgAoAAIAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAsAAIAAA" +
                "AAAAAAAAAAAAAACQAAAAAAAAAJAAAAdQBzAGUAcgAuAHQAZQBzAHQAAAAJAAAAAAAAAAkAAABVAHMAZQByACAAVABlAHMAdAAAAAAAAAAA" +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAACAgAABwAAAFAEAAAHAAAAAQIAAAcAAAAEAgAABwAAAA" +
                "MCAAAHAAAACAIAAAcAAAAAAgAABwAAAAkCAAAHAAAABgIAAAcAAAAHAgAABwAAAPIBAAAHAAAABwAAAAAAAAAGAAAAVwBTADIAMAAwADgA" +
                "BwAAAAAAAAAGAAAARABPAE0AQQBJAE4ABAAAAAEEAAAAAAAFFQAAAELcI/DfA8DDi6apKQcAAAAwAAIABwAAIDQAAgAHAAAgOAACAAcAAC" +
                "A8AAIABwAAIEAAAgAHAAAgRAACAAcAACBIAAIABwAAIAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSk8AgAABQAAAAEFAAAAAAAFFQAA" +
                "AELcI/DfA8DDi6apKTsCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkp6QMAAAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSnoAw" +
                "AABQAAAAEFAAAAAAAFFQAAAELcI / DfA8DDi6apKQUCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkpTwQAAAUAAAABBQAAAAAABR" +
                "UAAABC3CPw3wPAw4umqSkpAgAAAL9Len5yyQESAHUAcwBlAHIALgB0AGUAcwB0AAAAAAAoABAAFAA4AAAAAAAAAAAAdQBzAGUAcgAuAHQA" +
                "ZQBzAHQAQABkAG8AbQBhAGkAbgAuAGMAbwBtAEQATwBNAEEASQBOAC4AQwBPAE0AAAAAAHb///8AAAAAAAAAAAAAAAAAAAAAAAAAAHb//" +
                "/8AAAAAAAAAAAAAAAAAAAAAAAAAAA==";

        private const string AES128PACSIGNATURE = "DwAAAKPYyDLq7MP4qie/GQ==";
        private const string AES128PAC =
           "BQAAAAAAAAABAAAAIAMAAFgAAAAAAAAACgAAABwAAAB4AwAAAAAAAAwAAABQAAAAmAMAAAAAAAAGAAAAEAAAAOgDAAAAAAAA" +
          "BwAAABQAAAD4AwAAAAAAAAEQCADMzMzMEAMAAAAAAAAAAAIAwAycyX9yyQH/////////f/////////9/4Cg/sn9yyQHg6KjcS" +
          "HPJAf////////9/EgASAAQAAgASABIACAACAAAAAAAMAAIAAAAAABAAAgAAAAAAFAACAAAAAAAYAAIAMgAAAFIEAAABAgAACw" +
          "AAABwAAgAgAAAAAAAAAAAAAAAAAAAAAAAAAAwADgAgAAIADAAOACQAAgAoAAIAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAAAAAA" +
          "AAAAAAAAAAAAAAAAAAAcAAAAsAAIAAAAAAAAAAAAAAAAACQAAAAAAAAAJAAAAdQBzAGUAcgAuAHQAZQBzAHQAAAAJAAAAAAAA" +
          "AAkAAABVAHMAZQByACAAVABlAHMAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
          "AsAAAACAgAABwAAAFAEAAAHAAAAAQIAAAcAAAAEAgAABwAAAAMCAAAHAAAACAIAAAcAAAAAAgAABwAAAAkCAAAHAAAABgIAAA" +
          "cAAAAHAgAABwAAAPIBAAAHAAAABwAAAAAAAAAGAAAAVwBTADIAMAAwADgABwAAAAAAAAAGAAAARABPAE0AQQBJAE4ABAAAAAE" +
          "EAAAAAAAFFQAAAELcI/DfA8DDi6apKQcAAAAwAAIABwAAIDQAAgAHAAAgOAACAAcAACA8AAIABwAAIEAAAgAHAAAgRAACAAcA" +
          "ACBIAAIABwAAIAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSk8AgAABQAAAAEFAAAAAAAFFQAAAELcI/DfA8DDi6apKTsCA" +
          "AAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkp6QMAAAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSnoAwAABQAAAAEFAA" +
          "AAAAAFFQAAAELcI / DfA8DDi6apKQUCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkpTwQAAAUAAAABBQAAAAAABRUAA" +
          "ABC3CPw3wPAw4umqSkpAgAAgEkh / X9yyQESAHUAcwBlAHIALgB0AGUAcwB0AAAAAAAoABAAFAA4AAAAAAAAAAAAdQBzAGUA" +
          "cgAuAHQAZQBzAHQAQABkAG8AbQBhAGkAbgAuAGMAbwBtAEQATwBNAEEASQBOAC4AQwBPAE0AAAAAAA8AAAAAAAAAAAAAAAAAA" +
          "AB2////AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        private const string AES256PACSIGNATURE = "EAAAAHcQyvz922ZFzfua7A==";
        private const string AES256PAC
                = "BQAAAAAAAAABAAAAIAMAAFgAAAAAAAAACgAAABwAAAB4AwAAAAAAAAwAAABQAAAAmAMAAAAAAAAGAAAAEAAAAOgDAAAAAAAAB" +
            "wAAABQAAAD4AwAAAAAAAAEQCADMzMzMEAMAAAAAAAAAAAIAsITafH9yyQH/////////f/////////9/4Cg/sn9yyQHg6KjcSHPJAf//" +
            "//////9/EgASAAQAAgASABIACAACAAAAAAAMAAIAAAAAABAAAgAAAAAAFAACAAAAAAAYAAIAMQAAAFIEAAABAgAACwAAABwAAgAgAAA" +
            "AAAAAAAAAAAAAAAAAAAAAAAwADgAgAAIADAAOACQAAgAoAAIAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "cAAAAsAAIAAAAAAAAAAAAAAAAACQAAAAAAAAAJAAAAdQBzAGUAcgAuAHQAZQBzAHQAAAAJAAAAAAAAAAkAAABVAHMAZQByACAAVABlA" +
            "HMAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAACAgAABwAAAFAEAAAHAAAAAQIA" +
            "AAcAAAAEAgAABwAAAAMCAAAHAAAACAIAAAcAAAAAAgAABwAAAAkCAAAHAAAABgIAAAcAAAAHAgAABwAAAPIBAAAHAAAABwAAAAAAAAA" +
            "GAAAAVwBTADIAMAAwADgABwAAAAAAAAAGAAAARABPAE0AQQBJAE4ABAAAAAEEAAAAAAAFFQAAAELcI/DfA8DDi6apKQcAAAAwAAIABw" +
            "AAIDQAAgAHAAAgOAACAAcAACA8AAIABwAAIEAAAgAHAAAgRAACAAcAACBIAAIABwAAIAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umq" +
            "Sk8AgAABQAAAAEFAAAAAAAFFQAAAELcI/DfA8DDi6apKTsCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkp6QMAAAUAAAABBQAA" +
            "AAAABRUAAABC3CPw3wPAw4umqSnoAwAABQAAAAEFAAAAAAAFFQAAAELcI / DfA8DDi6apKQUCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8" +
            "N8DwMOLpqkpTwQAAAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSkpAgAAACRGyX9yyQESAHUAcwBlAHIALgB0AGUAcwB0AAAAAAAo" +
            "ABAAFAA4AAAAAAAAAAAAdQBzAGUAcgAuAHQAZQBzAHQAQABkAG8AbQBhAGkAbgAuAGMAbwBtAEQATwBNAEEASQBOAC4AQwBPAE0AAAA" +
            "AABAAAAAAAAAAAAAAAAAAAAB2////AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public async Task KerberosValidatorBadKey()
        {
            var data = ReadDataFile("aes128-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(new KerberosKey(key, etype: EncryptionType.AES128_CTS_HMAC_SHA1_96)) { ValidateAfterDecrypt = DefaultActions };

            await validator.Validate(data);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void KerberosValidatorAes128ModifiedPac()
        {
            var key = ReadDataFile("aes128-key-data");

            var kerbKey = new KerberosKey(key);

            var pacValidated = ValidatePac(
                kerbKey,
                Convert.FromBase64String(AES128PACSIGNATURE),
                Convert.FromBase64String(AES128PAC)
            );

            Assert.IsTrue(pacValidated);

            GenerateCorruptPac(AES128PACSIGNATURE, AES128PAC).Validator.Validate(kerbKey);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void KerberosValidatorAes256ModifiedPac()
        {
            var key = ReadDataFile("aes256-key-data");

            var kerbKey = new KerberosKey(key);

            var pacValidated = ValidatePac(
                kerbKey,
                Convert.FromBase64String(AES256PACSIGNATURE),
                Convert.FromBase64String(AES256PAC)
            );

            Assert.IsTrue(pacValidated);

            GenerateCorruptPac(AES256PACSIGNATURE, AES256PAC).Validator.Validate(kerbKey);
        }

        [TestMethod]
        [ExpectedException(typeof(SecurityException))]
        public void KerberosValidatorRC4ModifiedPac()
        {
            var key = ReadDataFile("rc4-key-data");
            var kerbKey = new KerberosKey(key);

            var pacValidated = ValidatePac(
                kerbKey,
                Convert.FromBase64String(RC4PACSIGNATURE),
                Convert.FromBase64String(RC4PAC)
            );

            Assert.IsTrue(pacValidated);

            GenerateCorruptPac(RC4PACSIGNATURE, RC4PAC).Validator.Validate(kerbKey);
        }

        private static bool ValidatePac(KerberosKey kerbKey, byte[] infoBufferBytes, byte[] pacBytes)
        {
            bool pacValidated;

            try
            {
                var sig = new PacSignature() { SignatureData = pacBytes };
                sig.Unmarshal(infoBufferBytes);
                sig.Validator.Validate(kerbKey);
                pacValidated = true;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch
#pragma warning restore CA1031 // Do not catch general exception types
            {
                pacValidated = false;
            }

            return pacValidated;
        }

        private static PacSignature GenerateCorruptPac(string infoBuffer, string pac)
        {
            var infoBufferBytes = Convert.FromBase64String(infoBuffer);
            var pacBytes = Convert.FromBase64String(pac);

            var rand = new Random();

            for (var i = 20; i < 50; i++)
            {
                pacBytes[i] = (byte)rand.Next(0, 254);
            }

            var sig = new PacSignature() { SignatureData = pacBytes };
            sig.Unmarshal(infoBufferBytes);

            return sig;
        }

        private class FakeCryptoTransform : KerberosCryptoTransformer
        {
            public override int ChecksumSize => 32;

            public override int BlockSize => 32;

            public override int KeySize => 32;

            public override ChecksumType ChecksumType => (ChecksumType)(-1);

            public override EncryptionType EType => (EncryptionType)(-1);

            public override ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey key, KeyUsage usage)
            {
                return cipher;
            }

            public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage usage)
            {
                return data;
            }

            public override ReadOnlyMemory<byte> String2Key(KerberosKey key)
            {
                return new byte[this.KeySize];
            }
        }

        private class FakeChecksum : KerberosChecksum
        {
            public FakeChecksum(ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> data)
                : base(signature, data)
            {
            }

            public override int ChecksumSize => 200;

            protected override ReadOnlyMemory<byte> SignInternal(KerberosKey key)
            {
                return new byte[this.ChecksumSize];
            }

            protected override bool ValidateInternal(KerberosKey key)
            {
                return this.Signature.Span.SequenceEqual(new byte[this.ChecksumSize]);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void ThrowsUnknownChecksumType()
        {
            var principal = new FakeKerberosPrincipal("blah@lah.com");

            var pac = principal.GeneratePac();

            var kdcKey = new KerberosKey(new byte[234], etype: (EncryptionType)(-1));
            var serverKey = new KerberosKey(new byte[32], etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);

            CryptoService.UnregisterChecksumAlgorithm((ChecksumType)(-1));
            CryptoService.UnregisterCryptographicAlgorithm((EncryptionType)(-1));

            pac.Encode(kdcKey, serverKey);
        }

        [TestMethod]
        public void PacIgnoresUnknownKdcSignatureType()
        {
            var principal = new FakeKerberosPrincipal("blah@lah.com");

            var pac = principal.GeneratePac();

            var kdcKey = new KerberosKey(new byte[234], etype: (EncryptionType)(-1));
            var serverKey = new KerberosKey(new byte[32], etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);

            CryptoService.RegisterChecksumAlgorithm((ChecksumType)(-1), (signature, signatureData) => new FakeChecksum(signature, signatureData));
            CryptoService.RegisterCryptographicAlgorithm((EncryptionType)(-1), () => new FakeCryptoTransform());

            var encoded = pac.Encode(kdcKey, serverKey);

            CryptoService.UnregisterChecksumAlgorithm((ChecksumType)(-1));
            CryptoService.UnregisterCryptographicAlgorithm((EncryptionType)(-1));

            var roundtrip = new PrivilegedAttributeCertificate(
                new KrbAuthorizationData
                {
                    Type = AuthorizationDataType.AdWin2kPac,
                    Data = encoded
                },
                SignatureMode.Server
            );

            Assert.IsNotNull(roundtrip);

            roundtrip.ServerSignature.Validate(serverKey);

            Assert.AreEqual((ChecksumType)(-1), roundtrip.KdcSignature.Type);

            bool threw = false;

            try
            {
                roundtrip.KdcSignature.Validate(serverKey);
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            Assert.IsTrue(threw);
        }

        [TestMethod]
        public void PacHandlesCustomKdcSignatureType()
        {
            var principal = new FakeKerberosPrincipal("blah@lah.com");

            var pac = principal.GeneratePac();

            var kdcKey = new KerberosKey(new byte[234], etype: (EncryptionType)(-1));
            var serverKey = new KerberosKey(new byte[32], etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);

            CryptoService.RegisterChecksumAlgorithm((ChecksumType)(-1), (signature, signatureData) => new FakeChecksum(signature, signatureData));
            CryptoService.RegisterCryptographicAlgorithm((EncryptionType)(-1), () => new FakeCryptoTransform());

            var encoded = pac.Encode(kdcKey, serverKey);

            var roundtrip = new PrivilegedAttributeCertificate(
                new KrbAuthorizationData
                {
                    Type = AuthorizationDataType.AdWin2kPac,
                    Data = encoded
                },
                SignatureMode.Kdc
            );

            Assert.IsNotNull(roundtrip);

            roundtrip.ServerSignature.Validate(serverKey);

            Assert.AreEqual((ChecksumType)(-1), roundtrip.KdcSignature.Type);

            roundtrip.KdcSignature.Validate(serverKey);
        }

        [TestMethod]
        public void PacFailsOnUnknownKdcSignatureType()
        {
            var principal = new FakeKerberosPrincipal("blah@lah.com");

            var pac = principal.GeneratePac();

            var kdcKey = new KerberosKey(new byte[234], etype: (EncryptionType)(-1));
            var serverKey = new KerberosKey(new byte[32], etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);

            CryptoService.RegisterChecksumAlgorithm((ChecksumType)(-1), (signature, signatureData) => new FakeChecksum(signature, signatureData));
            CryptoService.RegisterCryptographicAlgorithm((EncryptionType)(-1), () => new FakeCryptoTransform());

            var encoded = pac.Encode(kdcKey, serverKey);

            CryptoService.UnregisterChecksumAlgorithm((ChecksumType)(-1));
            CryptoService.UnregisterCryptographicAlgorithm((EncryptionType)(-1));

            bool threw = false;

            try
            {
                _ = new PrivilegedAttributeCertificate(
                    new KrbAuthorizationData
                    {
                        Type = AuthorizationDataType.AdWin2kPac,
                        Data = encoded
                    },
                    SignatureMode.Kdc
                );
            }
            catch (InvalidOperationException)
            {
                threw = true;
            }

            Assert.IsTrue(threw);
        }

        [TestMethod]
        public async Task PacRoundtrip()
        {
            var keyBytes = ReadDataFile("rc4-key-data");
            var key = new KerberosKey(keyBytes, etype: EncryptionType.RC4_HMAC_NT);

            var pac = await GeneratePac();

            var encoded = pac.Encode(key, key);

            var pacDecoded = new PrivilegedAttributeCertificate(new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = encoded });

            pacDecoded.ServerSignature.Validator.Validate(key);
            pacDecoded.KdcSignature.Validator.Validate(key);
        }

        [TestMethod]
        public async Task ValidatorCheckPacLogonInfo()
        {
            var cert = await GeneratePac();

            var logonInfo = cert.LogonInfo;

            var expectedLogonTime = DateTimeOffset.Parse("1/9/2009 5:15:20 PM +00:00", CultureInfo.InvariantCulture);

            Assert.AreEqual(expectedLogonTime, Truncate(logonInfo.LogonTime));

            var expectedLogoffTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedLogoffTime, (DateTimeOffset)logonInfo.LogoffTime);

            var expectedKickOffTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedKickOffTime, (DateTimeOffset)logonInfo.KickOffTime);

            var expectedPwdLastChangeTime = DateTimeOffset.Parse("1/7/2009 2:33:58 PM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdLastChangeTime, Truncate(logonInfo.PwdLastChangeTime));

            var expectedPwdCanChangeTime = DateTimeOffset.Parse("1/8/2009 2:33:58 PM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdCanChangeTime, Truncate(logonInfo.PwdCanChangeTime));

            var expectedPwdMustChangeTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdMustChangeTime, (DateTimeOffset)logonInfo.PwdMustChangeTime);

            Assert.AreEqual(46, logonInfo.LogonCount);
            Assert.AreEqual(0, logonInfo.BadPasswordCount);
            Assert.AreEqual(UserFlags.LOGON_EXTRA_SIDS, logonInfo.UserFlags);

            Assert.AreEqual(
                UserAccountControlFlags.ADS_UF_LOCKOUT | UserAccountControlFlags.ADS_UF_NORMAL_ACCOUNT,
                logonInfo.UserAccountControl
            );

            Assert.AreEqual(0, logonInfo.SubAuthStatus);

            var expectedLastSuccessfulILogon = DateTimeOffset.Parse("1/1/1601 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedLastSuccessfulILogon, (DateTimeOffset)logonInfo.LastSuccessfulILogon);

            var expectedLastLastFailedILogon = DateTimeOffset.Parse("1/1/1601 12:00:00 AM +00:00", CultureInfo.InvariantCulture);

            Assert.AreEqual(expectedLastLastFailedILogon, (DateTimeOffset)logonInfo.LastFailedILogon);
            Assert.AreEqual("user.test", logonInfo.UserName.ToString());
            Assert.AreEqual("User Test", logonInfo.UserDisplayName.ToString());
            Assert.AreEqual(string.Empty, logonInfo.LogonScript.ToString());
            Assert.AreEqual(string.Empty, logonInfo.ProfilePath.ToString());
            Assert.AreEqual(string.Empty, logonInfo.HomeDirectory.ToString());
            Assert.AreEqual(string.Empty, logonInfo.HomeDrive.ToString());
            Assert.AreEqual("WS2008\0", logonInfo.ServerName.ToString());
            Assert.AreEqual("DOMAIN\0", logonInfo.DomainName.ToString());
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075", logonInfo.DomainSid.Value);
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075-1106", logonInfo.UserSid.Value);
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075-513", logonInfo.GroupSid.Value);
            Assert.AreEqual(11, logonInfo.GroupSids.Count());
            Assert.AreEqual(7, logonInfo.ExtraSids.Count());

            Assert.IsNull(logonInfo.ResourceDomainSid);
            Assert.IsNotNull(logonInfo.ResourceGroups);
            Assert.AreEqual(0, logonInfo.ResourceGroups.Count());
        }

        [TestMethod]
        public async Task ClientInfo()
        {
            var cert = await GeneratePac();

            Assert.IsNotNull(cert.ClientInformation);

            Assert.AreEqual("user.test", cert.ClientInformation.Name);
            Assert.AreEqual((DateTimeOffset)cert.ClientInformation.ClientId, DateTimeOffset.Parse("1/9/2009 5:19:50 PM +00:00", CultureInfo.InvariantCulture));
        }

        [TestMethod]
        public async Task UpnDomainInfo()
        {
            var cert = await GeneratePac();

            Assert.IsNotNull(cert.UpnDomainInformation);

            Assert.AreEqual("DOMAIN.COM", cert.UpnDomainInformation.Domain);
            Assert.AreEqual("user.test@domain.com", cert.UpnDomainInformation.Upn);
            Assert.AreEqual((UpnDomainFlags)0, cert.UpnDomainInformation.Flags);
        }

        [TestMethod]
        public void PacGenerationRoundtrip()
        {
            const string realm = "foo.com";

            KrbPrincipalName krbtgtName = KrbPrincipalName.WellKnown.Krbtgt(realm);

            var realmService = new FakeRealmService(realm);
            var krbtgt = realmService.Principals.Find(krbtgtName);
            var key = krbtgt.RetrieveLongTermCredential();

            var user = realmService.Principals.Find(KrbPrincipalName.FromString("user@foo.com"));

            var pac = user.GeneratePac();

            Assert.IsNotNull(pac);

            var encoded = pac.Encode(key, key);

            var decoded = new PrivilegedAttributeCertificate(new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = encoded });

            Assert.IsNotNull(decoded.LogonInfo);
        }

        [TestMethod]
        public void Parse31bSid()
        {
            var domainSid = new SecurityIdentifier(IdentifierAuthority.AadAuthority, new uint[] { 3579221639, 4203588899, 1178257358, 1362520493 }, 0).ToRpcSid();
            var userId = 4176169732;

            var sid = SecurityIdentifier.FromRpcSid(domainSid, userId);

            Assert.AreEqual("S-1-12-3579221639-4203588899-1178257358-1362520493-4176169732", sid.Value);
        }

        private static async Task<PrivilegedAttributeCertificate> GeneratePac()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(new KerberosKey(key, etype: EncryptionType.RC4_HMAC_NT)) { ValidateAfterDecrypt = DefaultActions };

            var result = await validator.Validate(data);

            var pac = result.Ticket.AuthorizationData
                .Where(d => d.Type == AuthorizationDataType.AdIfRelevant)
                .Select(d => d.DecodeAdIfRelevant()
                    .Where(a => a.Type == AuthorizationDataType.AdWin2kPac)
                ).First();

            return new PrivilegedAttributeCertificate(new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = pac.First().Data });
        }

        private static DateTimeOffset Truncate(DateTimeOffset dateTime)
        {
            if (dateTime == DateTimeOffset.MinValue || dateTime == DateTimeOffset.MaxValue)
            {
                return dateTime;
            }

            return dateTime.AddTicks(-(dateTime.Ticks % TimeSpan.FromSeconds(1).Ticks));
        }
    }
}
