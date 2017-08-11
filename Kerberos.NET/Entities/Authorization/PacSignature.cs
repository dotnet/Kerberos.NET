
namespace Kerberos.NET.Entities.Authorization
{
    public enum SignatureType : uint
    {
        KERB_CHECKSUM_HMAC_MD5 = 0xFFFFFF76,
        HMAC_SHA1_96_AES128 = 0x0000000F,
        HMAC_SHA1_96_AES256 = 0x00000010
    }

    public class PacSignature
    {
        public PacSignature(byte[] data)
        {
            var pacStream = new NdrBinaryReader(data);

            Type = (SignatureType)pacStream.ReadUnsignedInt();

            switch (Type)
            {
                case SignatureType.KERB_CHECKSUM_HMAC_MD5:
                    Signature = pacStream.Read(16);
                    break;
                case SignatureType.HMAC_SHA1_96_AES128:
                case SignatureType.HMAC_SHA1_96_AES256:
                    Signature = pacStream.Read(12);
                    break;
            }

            if (pacStream.Position < pacStream.Length)
            {
                RODCIdentifier = pacStream.ReadShort();
            }
        }

        public SignatureType Type { get; private set; }

        public byte[] Signature { get; private set; }

        public short RODCIdentifier { get; private set; }
    }
}
