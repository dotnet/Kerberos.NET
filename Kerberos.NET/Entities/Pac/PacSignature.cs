// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.InteropServices;
using Kerberos.NET.Crypto;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    public class PacSignature : PacObject
    {
        public PacSignature()
        {
        }

        public PacSignature(PacType ptype, EncryptionType etype)
        {
            this.PacType = ptype;
            this.Type = CryptoService.ConvertType(etype);

            this.Signature = SetSignatureValue(this.Type, size => new byte[size]);
        }

        private static byte[] SetSignatureValue(ChecksumType type, Func<int, byte[]> setterFunc)
        {
            var checksum = CryptoService.CreateChecksum(type);

            if (checksum == null)
            {
                throw new InvalidOperationException($"Unknown checksum type {type}");
            }

            return setterFunc(checksum.ChecksumSize);
        }

        [KerberosIgnore]
        public ReadOnlyMemory<byte> SignatureData { get; set; }

        [KerberosIgnore]
        protected KerberosChecksum Validator { get; set; }

        public ChecksumType Type { get; set; }

        public Memory<byte> Signature { get; set; }

        public short RODCIdentifier { get; set; }

        internal int SignaturePosition { get; set; }

        public override PacType PacType { get; }

        [KerberosIgnore]
        public bool Validated { get; private set; }

        [KerberosIgnore]
        public bool Ignored { get; internal set; }

        public override ReadOnlyMemory<byte> Marshal()
        {
            using (var buffer = new NdrBuffer())
            {
                buffer.WriteInt32LittleEndian((int)this.Type);
                buffer.WriteSpan(this.Signature.Span);

                if (this.RODCIdentifier > 0)
                {
                    buffer.WriteInt16LittleEndian(this.RODCIdentifier);
                }

                return buffer.ToMemory();
            }
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            var stream = new NdrBuffer(bytes);

            this.Type = (ChecksumType)stream.ReadInt32LittleEndian();

            this.SignaturePosition = stream.Offset;

            if (!this.Ignored)
            {
                this.Signature = SetSignatureValue(this.Type, size => stream.ReadFixedPrimitiveArray<byte>(size).ToArray());

                if (stream.BytesAvailable > 0)
                {
                    this.RODCIdentifier = stream.ReadInt16LittleEndian();
                }
            }
            else
            {
                this.Signature = stream.ReadMemory(stream.BytesAvailable).ToArray();
            }
        }

        public void Validate(KerberosKey key)
        {
            this.Validator = CryptoService.CreateChecksum(this.Type, this.Signature, this.SignatureData);

            if (this.Validator == null)
            {
                throw new InvalidOperationException($"Validator not set for checksum type {this.Type}");
            }

            this.Validator.Validate(key);

            this.Validated = true;
        }

        internal void Validate(KeyTable keytab, KrbPrincipalName sname)
        {
            var key = keytab.GetKey(this.Type, sname);

            this.Validate(key);
        }

        internal void Sign(Memory<byte> pacUnsigned, KerberosKey key)
        {
            this.Validator = CryptoService.CreateChecksum(this.Type, this.Signature, pacUnsigned);

            this.Validator.Sign(key);

            this.Signature = MemoryMarshal.AsMemory(this.Validator.Signature);

            this.IsDirty = true;
        }
    }
}
