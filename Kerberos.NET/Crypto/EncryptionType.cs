﻿namespace Kerberos.NET.Crypto
{
    public enum EncryptionType : long
    {
        NULL = 0,
        DES_CBC_CRC = 1,
        DES_CBC_MD4 = 2,
        DES_CBC_MD5 = 3,
        AES128_CTS_HMAC_SHA1_96 = 17,
        AES256_CTS_HMAC_SHA1_96 = 18,
        DES_CBC_MD5_NT = 20,
        RC4_HMAC_NT = 23,
        RC4_HMAC_NT_EXP = 24,
        RC4_MD4 = -128,
        RC4_PLAIN2 = -129,
        RC4_LM = -130,
        RC4_SHA = -131,
        DES_PLAIN = -132,
        RC4_HMAC_OLD = -133,
        RC4_PLAIN_OLD = -134,
        RC4_HMAC_OLD_EXP = -135,
        RC4_PLAIN_OLD_EXP = -136,
        RC4_PLAIN = -140,
        RC4_PLAIN_EXP = -141,
        AES128_CTS_HMAC_SHA1_96_PLAIN = -148,
        AES256_CTS_HMAC_SHA1_96_PLAIN = -149
    }

    public enum SupportedEncryptionTypes : long
    {
        DesCbcCrc = 1 << 0,
        DesCbcMd5 = 1 << 1,
        Rc4Hmac = 1 << 2,
        Aes128CtsHmacSha196 = 1 << 3,
        Aes256CtsHmacSha196 = 1 << 4,

        FastSupported = 1 << 18,
        CompoundIdentitySupported = 1 << 19,
        ClaimsSupported = 1 << 20,
        ResourceSidCompressionDisabled = 1 << 21
    }
}
