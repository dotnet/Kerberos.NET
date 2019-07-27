using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities.Pac
{
    public class PacSignature : NdrObject, IPacElement
    {
        public PacSignature() { }

        public PacSignature(PacType ptype, EncryptionType etype)
        {
            PacType = ptype;
            Type = CryptoService.ConvertType(etype);

            Signature = SetSignatureValue(Type, size => new byte[size]);
        }

        private static byte[] SetSignatureValue(ChecksumType type, Func<int, byte[]> setterFunc)
        {
            switch (type)
            {
                case ChecksumType.KERB_CHECKSUM_HMAC_MD5:
                    return setterFunc(16);
                case ChecksumType.HMAC_SHA1_96_AES128:
                    return setterFunc(12);
                case ChecksumType.HMAC_SHA1_96_AES256:
                    return setterFunc(12);
            }

            throw new InvalidOperationException($"Unknown checksum type {type}");
        }

        private readonly byte[] signatureData;

        public PacSignature(byte[] signatureData)
        {
            this.signatureData = signatureData;
        }

        public KerberosChecksum Validator { get; set; }

        public ChecksumType Type { get; set; }

        public byte[] Signature { get; set; }

        public short RODCIdentifier { get; set; }

        internal int SignaturePosition { get; set; }

        public PacType PacType { get; }

        public bool Validated { get; private set; }

        public override void ReadBody(NdrBinaryStream stream)
        {
            Type = (ChecksumType)stream.ReadUnsignedInt();

            SignaturePosition = (int)stream.Position;
            Signature = SetSignatureValue(Type, size => stream.Read(size));

            Validator = CryptoService.CreateChecksumValidator(Type, Signature, signatureData);

            if (stream.Position < stream.Length)
            {
                RODCIdentifier = stream.ReadShort();
            }
        }

        public override void WriteBody(NdrBinaryStream stream)
        {
            stream.WriteUnsignedInt((int)Type);

            stream.WriteBytes(Signature);

            stream.WriteShort(RODCIdentifier);
        }

        internal void Validate(KeyTable keytab, KrbPrincipalName sname)
        {
            var key = keytab.GetKey(Type, sname);

            Validator.Validate(key);

            Validated = true;
        }

        internal void Sign(Memory<byte> pacUnsigned, KerberosKey key)
        {
            Validator = CryptoService.CreateChecksumValidator(Type, Signature, pacUnsigned.ToArray());

            Validator.Sign(key);

            this.Signature = Validator.Signature.ToArray();

            IsDirty = true;
        }
    }
}
