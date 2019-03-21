using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities.Authorization
{
    public class PacSignature
    {
        public PacSignature(byte[] infoBuffer, ref byte[] signatureData)
        {
            var pacStream = new NdrBinaryReader(infoBuffer);

            Type = (ChecksumType)pacStream.ReadUnsignedInt();

            SignaturePosition = (int)pacStream.Position;

            switch (Type)
            {
                case ChecksumType.KERB_CHECKSUM_HMAC_MD5:
                    Signature = pacStream.Read(16);
                    Validator = new HmacMd5PacValidator(Signature, ref signatureData);
                    break;
                case ChecksumType.HMAC_SHA1_96_AES128:
                    Signature = pacStream.Read(12);
                    Validator = new HmacAes128PacValidator(Signature, ref signatureData);
                    break;
                case ChecksumType.HMAC_SHA1_96_AES256:
                    Signature = pacStream.Read(12);
                    Validator = new HmacAes256PacValidator(Signature, ref signatureData);
                    break;
            }

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
