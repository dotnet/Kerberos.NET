using System;
using System.Buffers.Binary;
using System.Linq;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class Rfc8009Tests
    {
        private const string Aes128Sha256BaseKey = "37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C";
        private const string Aes256Sha384BaseKey = "6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52";
        private const string LessThanOneBlock = "00 01 02 03 04 05";
        private const string CompleteOneBlock = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F";
        private const string MoreThanOneBlock = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14";

        private static byte[] HexToByte(string hex)
        {
            hex = hex.Replace(" ", "").Replace("0x", "").Replace(",", "");

            return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                     .ToArray();
        }

        [TestMethod]
        public void Aes128_Sha256_Iter32768()
        {
            Rfc2898DeriveBytes.AttemptReflectionLookup = true;

            /*
             * Iteration count = 32768
             * Pass phrase = "password"
             * Saltp for creating 128-bit base-key:
             *     61 65 73 31 32 38 2D 63 74 73 2D 68 6D 61 63 2D
             *     73 68 61 32 35 36 2D 31 32 38 00 10 DF 9D D7 83
             *     e5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E
             *     41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E
             *
             * (The saltp is "aes128-cts-hmac-sha256-128" | 0x00 |
             *     random 16-byte valid UTF-8 sequence | "ATHENA.MIT.EDUraeburn")
             * 128-bit base-key:
             *     08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7
             */

            var expectedBytes = HexToByte("08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7");
            var saltBytes = HexToByte("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E");

            AES128Sha256TransformerEx transformer = new AES128Sha256TransformerEx();

            var iterations = new byte[4];

            BinaryPrimitives.WriteInt32BigEndian(iterations, 32768);

            var key = transformer.String2Key(
                new KerberosKey(
                    "password",
                    saltBytes: saltBytes,
                    etype: EncryptionType.AES128_CTS_HMAC_SHA256_128,
                    iterationParams: iterations
                )
            );

            AssertArrayEquals(expectedBytes, key);

            Assert.IsTrue(Rfc2898DeriveBytes.AttemptReflectionLookup);
        }

        [TestMethod]
        public void Aes128_Sha256_Iter32768_Managed()
        {
            Rfc2898DeriveBytes.AttemptReflectionLookup = false;

            /*
             * Iteration count = 32768
             * Pass phrase = "password"
             * Saltp for creating 128-bit base-key:
             *     61 65 73 31 32 38 2D 63 74 73 2D 68 6D 61 63 2D
             *     73 68 61 32 35 36 2D 31 32 38 00 10 DF 9D D7 83
             *     e5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E
             *     41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E
             *
             * (The saltp is "aes128-cts-hmac-sha256-128" | 0x00 |
             *     random 16-byte valid UTF-8 sequence | "ATHENA.MIT.EDUraeburn")
             * 128-bit base-key:
             *     08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7
             */

            var expectedBytes = HexToByte("08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7");
            var saltBytes = HexToByte("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E");

            AES128Sha256TransformerEx transformer = new AES128Sha256TransformerEx();

            var iterations = new byte[4];

            BinaryPrimitives.WriteInt32BigEndian(iterations, 32768);

            var key = transformer.String2Key(
                new KerberosKey(
                    "password",
                    saltBytes: saltBytes,
                    etype: EncryptionType.AES128_CTS_HMAC_SHA256_128,
                    iterationParams: iterations
                )
            );

            AssertArrayEquals(expectedBytes, key);

            Assert.IsFalse(Rfc2898DeriveBytes.AttemptReflectionLookup);
        }

        [TestMethod]
        public void Aes256_Sha384_Iter32768()
        {
            Rfc2898DeriveBytes.AttemptReflectionLookup = true;

            /*
             * Saltp for creating 256-bit base-key:
             *     61 65 73 32 35 36 2D 63 74 73 2D 68 6D 61 63 2D
             *     73 68 61 33 38 34 2D 31 39 32 00 10 DF 9D D7 83
             *     e5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E
             *     41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E
             * (The saltp is "aes256-cts-hmac-sha384-192" | 0x00 |
             *     random 16-byte valid UTF-8 sequence | "ATHENA.MIT.EDUraeburn")
             * 256-bit base-key:
             *     45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22
             *     36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67
             */

            var expectedBytes = HexToByte("45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22 36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67");
            var saltBytes = HexToByte("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E");

            AES256Sha384Transformer transformer = new AES256Sha384Transformer();

            var iterations = new byte[4];

            BinaryPrimitives.WriteInt32BigEndian(iterations, 32768);

            var key = transformer.String2Key(
                new KerberosKey(
                    "password",
                    saltBytes: saltBytes,
                    etype: EncryptionType.AES256_CTS_HMAC_SHA384_192,
                    iterationParams: iterations
                )
            );

            AssertArrayEquals(expectedBytes, key);
            Assert.IsTrue(Rfc2898DeriveBytes.AttemptReflectionLookup);
        }

        [TestMethod]
        public void Aes256_Sha384_Iter32768_Managed()
        {
            /*
             * Saltp for creating 256-bit base-key:
             *     61 65 73 32 35 36 2D 63 74 73 2D 68 6D 61 63 2D
             *     73 68 61 33 38 34 2D 31 39 32 00 10 DF 9D D7 83
             *     e5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E
             *     41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E
             * (The saltp is "aes256-cts-hmac-sha384-192" | 0x00 |
             *     random 16-byte valid UTF-8 sequence | "ATHENA.MIT.EDUraeburn")
             * 256-bit base-key:
             *     45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22
             *     36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67
             */

            Rfc2898DeriveBytes.AttemptReflectionLookup = false;

            var expectedBytes = HexToByte("45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22 36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67");
            var saltBytes = HexToByte("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E");

            AES256Sha384Transformer transformer = new AES256Sha384Transformer();

            var iterations = new byte[4];

            BinaryPrimitives.WriteInt32BigEndian(iterations, 32768);

            var key = transformer.String2Key(
                new KerberosKey(
                    "password",
                    saltBytes: saltBytes,
                    etype: EncryptionType.AES256_CTS_HMAC_SHA384_192,
                    iterationParams: iterations
                )
            );

            AssertArrayEquals(expectedBytes, key);
            Assert.IsFalse(Rfc2898DeriveBytes.AttemptReflectionLookup);
        }

        [TestMethod]
        public void Aes128_KeyDerivation_Encrypt()
        {
            /*
             * enctype aes128-cts-hmac-sha256-128:
             * 128-bit base-key:
             *     37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C
             * Kc value for key usage 2 (label = 0x0000000299):
             *     B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3
             * Ke value for key usage 2 (label = 0x00000002AA):
             *     9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E
             * Ki value for key usage 2 (label = 0x0000000255):
             *     9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C
             */

            var key = new KerberosKey(key: HexToByte(Aes128Sha256BaseKey));
            var expected = HexToByte("9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E");

            var transformer = new AES128Sha256TransformerEx();

            var derived = transformer.GetOrDeriveKey(key, KeyUsage.Ticket, KeyDerivationMode.Ke);

            AssertArrayEquals(expected, derived);
        }

        [TestMethod]
        public void Aes128_KeyDerivation_Checksum()
        {
            /*
             * enctype aes128-cts-hmac-sha256-128:
             * 128-bit base-key:
             *     37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C
             * Kc value for key usage 2 (label = 0x0000000299):
             *     B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3
             * Ke value for key usage 2 (label = 0x00000002AA):
             *     9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E
             * Ki value for key usage 2 (label = 0x0000000255):
             *     9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C
             */

            var key = new KerberosKey(key: HexToByte(Aes128Sha256BaseKey));
            var expected = HexToByte("B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3");

            var transformer = new AES128Sha256TransformerEx();

            var derived = transformer.GetOrDeriveKey(key, KeyUsage.Ticket, KeyDerivationMode.Kc);

            AssertArrayEquals(expected, derived);
        }

        [TestMethod]
        public void Aes128_KeyDerivation_Integrity()
        {
            /*
             * enctype aes128-cts-hmac-sha256-128:
             * 128-bit base-key:
             *     37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C
             * Kc value for key usage 2 (label = 0x0000000299):
             *     B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3
             * Ke value for key usage 2 (label = 0x00000002AA):
             *     9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E
             * Ki value for key usage 2 (label = 0x0000000255):
             *     9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C
             */

            var key = new KerberosKey(key: HexToByte(Aes128Sha256BaseKey));
            var expected = HexToByte("9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C");

            var transformer = new AES128Sha256TransformerEx();

            var derived = transformer.GetOrDeriveKey(key, KeyUsage.Ticket, KeyDerivationMode.Ki);

            AssertArrayEquals(expected, derived);
        }

        [TestMethod]
        public void Aes128_Encrypt_Sha256_SingleBlock()
        {
            /*
             * Plaintext: (length equals block size)
             *     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
             * Confounder:
             *     56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F
             * 128-bit AES key (Ke):
             *     9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E
             * 128-bit HMAC key (Ki):
             *     9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C
             * AES Output:
             *     35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A
             *     e0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2
             * Truncated HMAC Output:
             *     95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3
             * Ciphertext:
             *     35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A
             *     e0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2
             *     95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3
             */

            AssertEncryption(
                plaintextHex: CompleteOneBlock,
                confounderHex: "56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F",
                keyHex: Aes128Sha256BaseKey,
                expectedBytesHex: "35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2 95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3",
                new AES128Sha256TransformerEx()
            );
        }

        [TestMethod]
        public void Aes128_Encrypt_Sha256_Roundtrip()
        {
            /*
             * Plaintext: (length equals block size)
             *     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
             * Confounder:
             *     56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F
             * 128-bit AES key (Ke):
             *     9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E
             * 128-bit HMAC key (Ki):
             *     9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C
             * AES Output:
             *     35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A
             *     e0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2
             * Truncated HMAC Output:
             *     95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3
             * Ciphertext:
             *     35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A
             *     e0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2
             *     95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3
             */

            var key = new KerberosKey(key: HexToByte(Aes128Sha256BaseKey), etype: EncryptionType.AES128_CTS_HMAC_SHA256_128);

            var plaintext = HexToByte(CompleteOneBlock);
            var expectedBytes = HexToByte("35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2 95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3");

            AES128Sha256TransformerEx transformer = new AES128Sha256TransformerEx();

            transformer.SetConfounder(HexToByte("56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F"));

            var output = transformer.Encrypt(
                plaintext,
                key,
                KeyUsage.Ticket
            );

            AssertArrayEquals(expectedBytes, output);

            var decrypted = transformer.Decrypt(output, key, KeyUsage.Ticket);

            AssertArrayEquals(plaintext, decrypted);
        }

        [TestMethod]
        public void Aes128_Encrypt_Sha256_EmptyBlock()
        {
            /*
             * Plaintext: (empty)
             * Confounder:
             *     7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48
             * 128-bit AES key (Ke):
             *     9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E
             * 128-bit HMAC key (Ki):
             *     9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C
             * AES Output:
             *     EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D
             * Truncated HMAC Output:
             *     AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18
             * Ciphertext (AES Output | HMAC Output):
             *     EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D
             *     AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18
             */

            AssertEncryption(
                plaintextHex: "",
                confounderHex: "7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48",
                keyHex: Aes128Sha256BaseKey,
                expectedBytesHex: "EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18",
                new AES128Sha256TransformerEx()
            );
        }

        [TestMethod]
        public void Aes128_Encrypt_Sha256_SmallBlock()
        {
            /*
             * Plaintext: (length less than block size)
             *     00 01 02 03 04 05
             * Confounder:
             *     7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24
             * 128-bit AES key (Ke):
             *     9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E
             * 128-bit HMAC key (Ki):
             *     9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C
             * AES Output:
             *     84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF
             *     B5 54 02 CE F7 E6
             * Truncated HMAC Output:
             *     87 7C E9 9E 24 7E 52 D1 6E D4 42 1D FD F8 97 6C
             * Ciphertext:
             *     84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF
             *     B5 54 02 CE F7 E6 87 7C E9 9E 24 7E 52 D1 6E D4
             *     42 1D FD F8 97 6C
             */

            AssertEncryption(
               plaintextHex: LessThanOneBlock,
               confounderHex: "7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24",
               keyHex: Aes128Sha256BaseKey,
               expectedBytesHex: "84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF B5 54 02 CE F7 E6 87 7C E9 9E 24 7E 52 D1 6E D4 42 1D FD F8 97 6C",
               new AES128Sha256TransformerEx()
           );
        }

        [TestMethod]
        public void Aes128_Encrypt_Sha256_LargeBlocks()
        {
            /*
             * Plaintext: (length greater than block size)
             *     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
             *     10 11 12 13 14
             * Confounder:
             *     A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC
             * 128-bit AES key (Ke):
             *     9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E
             * 128-bit HMAC key (Ki):
             *     9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C
             * AES Output:
             *     72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36
             * C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC
             *     E1 E6 D0 72 C1
             * Truncated HMAC Output:
             *     86 B3 9A 41 3C 2F 92 CA 9B 83 34 A2 87 FF CB FC
             * Ciphertext:
             *     72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36
             *     C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC
             *     E1 E6 D0 72 C1 86 B3 9A 41 3C 2F 92 CA 9B 83 34
             *     A2 87 FF CB FC
             */

            AssertEncryption(
               plaintextHex: MoreThanOneBlock,
               confounderHex: "A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC",
               keyHex: Aes128Sha256BaseKey,
               expectedBytesHex: "72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36 C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC E1 E6 D0 72 C1 86 B3 9A 41 3C 2F 92 CA 9B 83 34 A2 87 FF CB FC",
               new AES128Sha256TransformerEx()
           );
        }

        [TestMethod]
        public void Aes256_Encrypt_Sha384_EmptyBlock()
        {
            /*
             * Plaintext: (empty)
             * Confounder:
             *     F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4
             * 256-bit AES key (Ke):
             *     56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
             *     A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49
             * 192-bit HMAC key (Ki):
             *     69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
             *     22 C4 D0 0F FC 23 ED 1F
             * AES Output:
             *     41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0
             * Truncated HMAC Output:
             *     58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74
             *     8B 9B BF BE 7E B4 CE 3C
             * Ciphertext:
             *     41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0
             *     58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74
             *     8B 9B BF BE 7E B4 CE 3C
             */

            AssertEncryption(
               plaintextHex: "",
               confounderHex: "F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4",
               keyHex: Aes256Sha384BaseKey,
               expectedBytesHex: "41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0 58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74 8B 9B BF BE 7E B4 CE 3C",
               new AES256Sha384TransformerEx()
            );
        }

        [TestMethod]
        public void Aes256_Encrypt_Sha384_SmallBlock()
        {
            /*
             * Plaintext: (length less than block size)
             *     00 01 02 03 04 05
             * Confounder:
             *     B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A
             * 256-bit AES key (Ke):
             *     56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
             *     A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49
             * 192-bit HMAC key (Ki):
             *     69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
             *     22 C4 D0 0F FC 23 ED 1F
             * AES Output:
             *     4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7
             *     B7 5F B3 F6 37 B9
             * Truncated HMAC Output:
             *     F5 59 C7 F6 64 F6 9E AB 7B 60 92 23 75 26 EA 0D
             *     1F 61 CB 20 D6 9D 10 F2
             * Ciphertext:
             *     4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7
             *     B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60
             *     92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2
             */

            AssertEncryption(
               plaintextHex: LessThanOneBlock,
               confounderHex: "B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A",
               keyHex: Aes256Sha384BaseKey,
               expectedBytesHex: "4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7 B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60 92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2",
               new AES256Sha384TransformerEx()
            );
        }

        [TestMethod]
        public void Aes256_Encrypt_Sha384_SingleBlock()
        {
            /*
             * Plaintext: (length equals block size)
             *     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
             * Confounder:
             *     53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63
             * 256-bit AES key (Ke):
             *     56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
             *     A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49
             * 192-bit HMAC key (Ki):
             *     69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
             *     22 C4 D0 0F FC 23 ED 1F
             * AES Output:
             *     BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B
             *     BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6
             * Truncated HMAC Output:
             *     8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E
             *     40 C4 FF 25 5B 36 A2 66
             * Ciphertext:
             *     BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B
             *     BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6
             *     8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E
             *     40 C4 FF 25 5B 36 A2 66
             */

            AssertEncryption(
               plaintextHex: CompleteOneBlock,
               confounderHex: "53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63",
               keyHex: Aes256Sha384BaseKey,
               expectedBytesHex: "BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6 8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E 40 C4 FF 25 5B 36 A2 66",
               new AES256Sha384TransformerEx()
            );
        }

        [TestMethod]
        public void Aes256_Encrypt_Sha384_LargeBlocks()
        {
            /*
             * Plaintext: (length greater than block size)
             *     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
             *     10 11 12 13 14
             * Confounder:
             *     76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1
             * 256-bit AES key (Ke):
             *     56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
             *     A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49
             * 192-bit HMAC key (Ki):
             *     69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
             *     22 C4 D0 0F FC 23 ED 1F
             * AES Output:
             *     40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE
             *     10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2
             *     B2 A6 02 AC 86
             * Truncated HMAC Output:
             *     FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08
             *     D2 C1 6B 41 92 E0 1F 62
             * Ciphertext:
             *     40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE
             *     10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2
             *     B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A
             *     1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62
             */

            AssertEncryption(
               plaintextHex: MoreThanOneBlock,
               confounderHex: "76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1",
               keyHex: Aes256Sha384BaseKey,
               expectedBytesHex: "40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE 10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2 B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62",
               new AES256Sha384TransformerEx()
            );
        }

        [TestMethod]
        public void Aes256_KeyDerivation_Encrypt()
        {
            /*
             * 256-bit base-key:
             *     6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98
             *     00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52
             * Kc value for key usage 2 (label = 0x0000000299):
             *     EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4
             *     BA 41 F2 8F AF 69 E7 3D
             * Ke value for key usage 2 (label = 0x00000002AA):
             *     56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
             *     A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49
             * Ki value for key usage 2 (label = 0x0000000255):
             *     69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
             *     22 C4 D0 0F FC 23 ED 1F
             */

            var key = new KerberosKey(key: HexToByte(Aes256Sha384BaseKey));
            var expected = HexToByte("56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49");

            var transformer = new AES256Sha384TransformerEx();

            var derived = transformer.GetOrDeriveKey(key, KeyUsage.Ticket, KeyDerivationMode.Ke);

            AssertArrayEquals(expected, derived);
        }

        [TestMethod]
        public void Aes256_KeyDerivation_Checksum()
        {
            /*
             * 256-bit base-key:
             *     6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98
             *     00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52
             * Kc value for key usage 2 (label = 0x0000000299):
             *     EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4
             *     BA 41 F2 8F AF 69 E7 3D
             * Ke value for key usage 2 (label = 0x00000002AA):
             *     56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
             *     A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49
             * Ki value for key usage 2 (label = 0x0000000255):
             *     69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
             *     22 C4 D0 0F FC 23 ED 1F
             */

            var key = new KerberosKey(key: HexToByte(Aes256Sha384BaseKey));
            var expected = HexToByte("EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D");

            var transformer = new AES256Sha384TransformerEx();

            var derived = transformer.GetOrDeriveKey(key, KeyUsage.Ticket, KeyDerivationMode.Kc);

            AssertArrayEquals(expected, derived.Slice(0, 24));
        }

        [TestMethod]
        public void Aes256_KeyDerivation_Integrity()
        {
            /*
             * 256-bit base-key:
             *     6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98
             *     00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52
             * Kc value for key usage 2 (label = 0x0000000299):
             *     EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4
             *     BA 41 F2 8F AF 69 E7 3D
             * Ke value for key usage 2 (label = 0x00000002AA):
             *     56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
             *     A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49
             * Ki value for key usage 2 (label = 0x0000000255):
             *     69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
             *     22 C4 D0 0F FC 23 ED 1F
             */

            var key = new KerberosKey(key: HexToByte(Aes256Sha384BaseKey));
            var expected = HexToByte("69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F");

            var transformer = new AES256Sha384TransformerEx();

            var derived = transformer.GetOrDeriveKey(key, KeyUsage.Ticket, KeyDerivationMode.Ki);

            AssertArrayEquals(expected, derived.Slice(0, 24));
        }

        [TestMethod]
        public void Aes128Sha256_Hmac()
        {
            /*
             * Checksum type: hmac-sha256-128-aes128
             * 128-bit HMAC key (Kc):
             *     B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3
             * Plaintext:
             *     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
             *     10 11 12 13 14
             * Checksum:
             *     D7 83 67 18 66 43 D6 7B 41 1C BA 91 39 FC 1D EE
             */

            AssertChecksum(
                plaintextHex: MoreThanOneBlock,
                keyHex: Aes128Sha256BaseKey,
                checksumHex: "D7 83 67 18 66 43 D6 7B 41 1C BA 91 39 FC 1D EE",
                ChecksumType.HMAC_SHA256_128_AES128
            );
        }

        [TestMethod]
        public void Aes256Sha384_Hmac()
        {
            /*
             * Checksum type: hmac-sha384-192-aes256
             * 192-bit HMAC key (Kc):
             *     EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4
             *     BA 41 F2 8F AF 69 E7 3D
             * Plaintext:
             *     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
             *     10 11 12 13 14
             * Checksum:
             *     45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D
             *     43 C3 BF A0 66 99 67 2A
             */

            AssertChecksum(
                plaintextHex: MoreThanOneBlock,
                keyHex: Aes256Sha384BaseKey,
                checksumHex: "45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D 43 C3 BF A0 66 99 67 2A",
                ChecksumType.HMAC_SHA384_192_AES256
            );
        }

        private static void AssertChecksum(string plaintextHex, string keyHex, string checksumHex, ChecksumType type)
        {
            var hmac = CryptoService.CreateChecksum(type, HexToByte(checksumHex), HexToByte(plaintextHex));

            hmac.Usage = KeyUsage.Ticket;

            var key = new KerberosKey(HexToByte(keyHex));

            hmac.Validate(key);
        }

        private static void AssertEncryption(string plaintextHex, string confounderHex, string keyHex, string expectedBytesHex, Rfc8009Transformer transformer)
        {
            var plaintext = HexToByte(plaintextHex);

            if (transformer is AES128Sha256TransformerEx t)
            {
                t.SetConfounder(HexToByte(confounderHex));
            }

            if (transformer is AES256Sha384TransformerEx t2)
            {
                t2.SetConfounder(HexToByte(confounderHex));
            }

            var key = new KerberosKey(key: HexToByte(keyHex));

            var output = transformer.Encrypt(
                plaintext,
                key,
                KeyUsage.Ticket
            );

            var expectedBytes = HexToByte(expectedBytesHex);

            AssertArrayEquals(expectedBytes, output);
        }

        private static void AssertArrayEquals(ReadOnlyMemory<byte> expectedBytes, ReadOnlyMemory<byte> actualBytes)
        {
            Assert.IsTrue(expectedBytes.Span.SequenceEqual(actualBytes.Span));
        }

        private class AES256Sha384TransformerEx : AES256Sha384Transformer
        {
            public void SetConfounder(ReadOnlyMemory<byte> con)
            {
                this.Confounder = con;
            }

            internal new ReadOnlyMemory<byte> GetOrDeriveKey(KerberosKey key, KeyUsage usage, KeyDerivationMode mode)
            {
                return base.GetOrDeriveKey(key, usage, mode);
            }
        }

        private class AES128Sha256TransformerEx : AES128Sha256Transformer
        {
            public void SetConfounder(ReadOnlyMemory<byte> con)
            {
                this.Confounder = con;
            }

            internal new ReadOnlyMemory<byte> GetOrDeriveKey(KerberosKey key, KeyUsage usage, KeyDerivationMode mode)
            {
                return base.GetOrDeriveKey(key, usage, mode);
            }
        }
    }
}
