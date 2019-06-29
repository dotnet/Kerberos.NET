namespace Kerberos.NET.Crypto
{
    public enum ChecksumType : long
    {
        KERB_CHECKSUM_HMAC_MD5 = 0xFFFFFF76,
        HMAC_SHA1_96_AES128 = 0x0000000F,
        HMAC_SHA1_96_AES256 = 0x00000010
    }
}
