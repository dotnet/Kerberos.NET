using Kerberos.NET.Crypto;
using Kerberos.NET.Ndr;
using System;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Entities.Pac
{
    public class PacSignature : PacObject
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
            byte[] signatureValue = null;

            switch (type)
            {
                case ChecksumType.KERB_CHECKSUM_HMAC_MD5:
                    signatureValue = setterFunc(16);
                    break;
                case ChecksumType.HMAC_SHA1_96_AES128:
                case ChecksumType.HMAC_SHA1_96_AES256:
                    signatureValue = setterFunc(12);
                    break;
                default:
                    throw new InvalidOperationException($"Unknown checksum type {type}");
            }

            return signatureValue;
        }

        public ReadOnlyMemory<byte> SignatureData { get; set; }

        public KerberosChecksum Validator { get; set; }

        public ChecksumType Type { get; set; }

        public Memory<byte> Signature { get; set; }

        public short RODCIdentifier { get; set; }

        internal int SignaturePosition { get; set; }

        public override PacType PacType { get; }

        public bool Validated { get; private set; }

        public override ReadOnlySpan<byte> Marshal()
        {
            var buffer = new NdrBuffer();

            buffer.WriteInt32LittleEndian((int)Type);
            buffer.WriteSpan(Signature.Span);

            if (RODCIdentifier > 0)
            {
                buffer.WriteInt16LittleEndian(RODCIdentifier);
            }

            return buffer.ToSpan();
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            var stream = new NdrBuffer(bytes);

            Type = (ChecksumType)stream.ReadInt32LittleEndian();

            SignaturePosition = stream.Offset;
            Signature = SetSignatureValue(Type, size => stream.ReadFixedPrimitiveArray<byte>(size).ToArray());

            Validator = CryptoService.CreateChecksum(Type, Signature, SignatureData);

            if (stream.BytesAvailable > 0)
            {
                RODCIdentifier = stream.ReadInt16LittleEndian();
            }
        }

        internal void Validate(KeyTable keytab, KrbPrincipalName sname)
        {
            var key = keytab.GetKey(Type, sname);

            Validator.Validate(key);

            Validated = true;
        }

        internal void Sign(Memory<byte> pacUnsigned, KerberosKey key)
        {
            Validator = CryptoService.CreateChecksum(Type, Signature, pacUnsigned);

            Validator.Sign(key);

            Signature = MemoryMarshal.AsMemory(Validator.Signature);

            IsDirty = true;
        }
    }
}
