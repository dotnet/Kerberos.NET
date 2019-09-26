namespace Kerberos.NET.Crypto
{
    public enum ChecksumType : int
    {
        KERB_CHECKSUM_HMAC_MD5 = unchecked((int)0xFFFFFF76),
        HMAC_SHA1_96_AES128 = 0x0000000F,
        HMAC_SHA1_96_AES256 = 0x00000010
    }
}
