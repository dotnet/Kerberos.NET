// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KeyTableTests : BaseTest
    {
        [TestMethod]
        public void KeyVersionOverride_32Bit()
        {
            var keyTable = new KeyTable(ReadDataFile("sample_with_32_bit_version_override.keytab"));

            Assert.IsNotNull(keyTable);
            Assert.AreEqual(2, keyTable.Entries.First().Version);
        }

        [TestMethod]
        public void TrailingPadding()
        {
            var keyTable = new KeyTable(ReadDataFile("sample_with_padding.keytab"));

            Assert.IsNotNull(keyTable);
            Assert.AreEqual(15, keyTable.Entries.Count);
            Assert.AreEqual(keyTable.Entries.First().EncryptionType, EncryptionType.DES_CBC_CRC);
            Assert.AreEqual(keyTable.Entries.Last().EncryptionType, EncryptionType.RC4_HMAC_NT);
        }

        [TestMethod]
        public void Roundtrip32bOverride()
        {
            var keytable = new KeyTable(ReadDataFile("sample_with_32_bit_version_override.keytab"));

            Assert.IsNotNull(keytable);
            Assert.AreEqual(1, keytable.Entries.Count);

            var buffer = new MemoryStream();

            using (var writer = new BinaryWriter(buffer))
            {
                keytable.Write(writer);

                var secondKeyTable = new KeyTable(buffer.ToArray());

                Assert.IsNotNull(secondKeyTable);
                Assert.AreEqual(1, secondKeyTable.Entries.Count);

                AssertKeytablesAreEqual(keytable, secondKeyTable);
            }
        }

        [TestMethod]
        public void RoundtripTrailingPadding()
        {
            var keytable = new KeyTable(ReadDataFile("sample_with_padding.keytab"));

            Assert.IsNotNull(keytable);
            Assert.AreEqual(15, keytable.Entries.Count);

            var buffer = new MemoryStream();

            using (var writer = new BinaryWriter(buffer))
            {
                keytable.Write(writer);

                var secondKeyTable = new KeyTable(buffer.ToArray());

                Assert.IsNotNull(secondKeyTable);
                Assert.AreEqual(15, secondKeyTable.Entries.Count);

                AssertKeytablesAreEqual(keytable, secondKeyTable);
            }
        }

        [TestMethod]
        public void RoundtripSimple()
        {
            var keytable = new KeyTable(ReadDataFile("sample.keytab"));

            Assert.IsNotNull(keytable);
            Assert.AreEqual(5, keytable.Entries.Count);

            var buffer = new MemoryStream();

            using (var writer = new BinaryWriter(buffer))
            {
                keytable.Write(writer);

                var secondKeyTable = new KeyTable(buffer.ToArray());

                Assert.IsNotNull(secondKeyTable);
                Assert.AreEqual(5, secondKeyTable.Entries.Count);

                AssertKeytablesAreEqual(keytable, secondKeyTable);
            }
        }

        [TestMethod]
        public void EncodeDecodeEmptyKey()
        {
            var kt = new KeyTable(
                new KerberosKey(key: new byte[16], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    principal: PrincipalName.FromKrbPrincipalName(KrbPrincipalName.FromString("user@domain.com"), "domain.com")),
                null,
                new KerberosKey(key: new byte[16], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    principal: PrincipalName.FromKrbPrincipalName(KrbPrincipalName.FromString("user@domain.com"), "domain.com"))
            );

            var buffer = new MemoryStream();

            using (var writer = new BinaryWriter(buffer))
            {
                kt.Write(writer);
            }

            var arr = buffer.ToArray();

            var kt2 = new KeyTable(arr);

            Assert.AreEqual(2, kt2.Entries.Count);
        }

        private static void AssertKeytablesAreEqual(KeyTable keytable, KeyTable secondKeyTable)
        {
            for (var i = 0; i < keytable.Entries.Count; i++)
            {
                Assert.AreEqual(keytable.Entries.ElementAt(i), secondKeyTable.Entries.ElementAt(i));
            }
        }

        [TestMethod]
        public void KeyGeneration()
        {
            var keys = new[]
            {
                new KerberosKey(
                    "password",
                    new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "REALM.COM", new[] { "host/appservice" }),
                    host: "appservice",
                    etype: EncryptionType.AES256_CTS_HMAC_SHA1_96
                )
            };

            var keytable = new KeyTable(keys);

            var buffer = new MemoryStream();

            using (var writer = new BinaryWriter(buffer))
            {
                keytable.Write(writer);

                var secondKeytab = new KeyTable(buffer.ToArray());

                AssertKeytablesAreEqual(keytable, secondKeytab);
            }
        }

        [TestMethod]
        public async Task Authenticator_SerializedKeytab()
        {
            var key = new KerberosKey(
                password: "P@ssw0rd!",
                principalName: new PrincipalName(
                    PrincipalNameType.NT_SRV_INST,
                    "IDENTITYINTERVENTION.COM",
                    new[] { "host", "aadg.windows.net.nsatc.net" }
                ),
                etype: EncryptionType.RC4_HMAC_NT
            );

            var keytab = new KeyTable(key);

            var buffer = new MemoryStream();

            using (var writer = new BinaryWriter(buffer))
            {
                keytab.Write(writer);

                var secondKeytab = new KeyTable(buffer.ToArray());

                var authenticator = new KerberosAuthenticator(
                    new KerberosValidator(secondKeytab)
                    {
                        ValidateAfterDecrypt = DefaultActions
                    });

                Assert.IsNotNull(authenticator);

                var result = await authenticator.Authenticate(RC4Header);

                Assert.IsNotNull(result);

                Assert.AreEqual("Administrator@identityintervention.com", result.Name);
            }
        }

        [TestMethod]
        public async Task Authenticator_RoundtripKeytab()
        {
            var keytab = new KeyTable(ReadDataFile("sample.keytab"));

            var buffer = new MemoryStream();

            using (var writer = new BinaryWriter(buffer))
            {
                keytab.Write(writer);

                var secondKeytab = new KeyTable(buffer.ToArray());

                var authenticator = new KerberosAuthenticator(
                    new KerberosValidator(secondKeytab)
                    {
                        ValidateAfterDecrypt = DefaultActions
                    });

                Assert.IsNotNull(authenticator);

                var result = await authenticator.Authenticate(RC4Header);

                Assert.IsNotNull(result);

                Assert.AreEqual("Administrator@identityintervention.com", result.Name);
            }
        }

        [TestMethod]
        public void KeyEntry_NotEquals()
        {
            var key = new KeyEntry(new KerberosKey(password: "blah"));

            Assert.IsFalse(key.Equals(123));
        }

        [TestMethod]
        public void KeyEntry_ToString()
        {
            var key = new KeyEntry(new KerberosKey(password: "blah", etype: EncryptionType.AES128_CTS_HMAC_SHA1_96));

            var str = key.ToString();

            Assert.AreEqual("V5 AES128_CTS_HMAC_SHA1_96", str);
        }

        [TestMethod]
        public void KerberosKeyIdMatches()
        {
            var key = KerberosKey.DeriveFromKeyId(
                "P@ssw0rd!",
                new Guid("0aa29dcb-3a9b-413f-aee2-8df91fd1118e"),
                KrbPrincipalName.FromString(
                    "host/test.identityintervention.com",
                    PrincipalNameType.NT_SRV_INST,
                    "corp.identityintervention.com"
                )
            );

            AssertKeyMatchesGuid(key.EncryptionType, key);
        }

        [TestMethod]
        public void KerberosKeyExportFile()
        {
            var file = KerberosKey.GenerateFile(
                "P@ssw0rd!",
                new Guid("0aa29dcb-3a9b-413f-aee2-8df91fd1118e"),
                KrbPrincipalName.FromString(
                    "host/test.identityintervention.com",
                    PrincipalNameType.NT_SRV_INST,
                    "corp.identityintervention.com"
                )
            );

            var keytab = new KeyTable(file.ToArray());

            Assert.AreEqual(1, keytab.Entries.Count);

            var key = keytab.Entries.First();

            var kerbKey = key.Key;

            AssertKeyMatchesGuid(key.EncryptionType.Value, kerbKey);
        }

        [TestMethod]
        public void MultipleVersionsInSameKeytab()
        {
            var keys = new[] {
                new KerberosKey(
                    "password",
                    new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "REALM.COM", new[] { "host/appservice" }),
                    host: "appservice",
                    etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    kvno: 1
                ),
                new KerberosKey(
                    "password",
                    new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "REALM.COM", new[] { "host/appservice" }),
                    host: "appservice",
                    etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    kvno: 2
                ),
                new KerberosKey(
                    "password",
                    new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "REALM.COM", new[] { "host/appservice" }),
                    host: "appservice",
                    etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    kvno: 12
                )
            };

            var keytable = new KeyTable(keys);
            var key = keytable.GetKey(EncryptionType.AES256_CTS_HMAC_SHA1_96, KrbPrincipalName.FromString("host/appservice"));
            Assert.AreEqual(12, key.Version);
        }

        private static void AssertKeyMatchesGuid(EncryptionType etype, KerberosKey kerbKey)
        {
            Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, etype);

            var derivedKey = kerbKey.GetKey(null);

            Assert.IsNotNull(derivedKey);

            var expectedKey = new byte[]
            {
                0xbc, 0x31, 0x7e, 0x82, 0x48, 0x55, 0xcb, 0xa0, 0x3f, 0x70, 0xbe, 0x93, 0x0a, 0xa5, 0x0f, 0xef,
                0x6a, 0x64, 0x7c, 0xc3, 0x99, 0x36, 0x63, 0xee, 0xa5, 0x39, 0x2f, 0xab, 0xd9, 0x01, 0xad, 0xce
            };

            Assert.IsTrue(expectedKey.SequenceEqual(derivedKey.ToArray()));
        }
    }
}
