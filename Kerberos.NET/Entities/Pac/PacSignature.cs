using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities.Pac
{
    public class PacSignature
    {
        public PacSignature(byte[] infoBuffer, byte[] signatureData)
        {
            var pacStream = new NdrBinaryReader(infoBuffer);

            Type = (ChecksumType)pacStream.ReadUnsignedInt();

            SignaturePosition = (int)pacStream.Position;

            switch (Type)
            {
                case ChecksumType.KERB_CHECKSUM_HMAC_MD5:
                    Signature = pacStream.Read(16);
                    break;
                case ChecksumType.HMAC_SHA1_96_AES128:
                    Signature = pacStream.Read(12);
                    break;
                case ChecksumType.HMAC_SHA1_96_AES256:
                    Signature = pacStream.Read(12);
                    break;
            }

            Validator = CryptographyService.CreateChecksumValidator(Type, Signature, signatureData);

            if (pacStream.Position < pacStream.Length)
            {
                RODCIdentifier = pacStream.ReadShort();
            }
        }

        public PacValidator Validator { get; }

        public ChecksumType Type { get; }

        public byte[] Signature { get; }

        public short RODCIdentifier { get; }

        public int SignaturePosition { get; }

        internal void Validate(KeyTable keytab, PrincipalName sname)
        {
            var key = keytab.GetKey(Type, sname);

            Validator.Validate(key);  
        }
    }
}
