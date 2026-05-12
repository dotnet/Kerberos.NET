// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// KRB-FINISHED structure for IAKerb GSS_EXTS_FINISHED extension.
    /// Contains a checksum of all preceding GSS-API context tokens.
    /// </summary>
    public class KrbFinished
    {
        /*
          KRB-FINISHED ::= SEQUENCE {
              gss-mic [1] Checksum,
          }
         */

        public const int GssExtsFinishedType = 2;

        public KrbChecksum GssMic { get; set; }

        public ReadOnlyMemory<byte> Encode()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            writer.PushSequence();

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            GssMic.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            writer.PopSequence();

            return writer.EncodeAsMemory();
        }

        public static KrbFinished Decode(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);
            var sequenceReader = reader.ReadSequence();

            var explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            KrbChecksum.Decode(explicitReader, out KrbChecksum checksum);

            explicitReader.ThrowIfNotEmpty();
            sequenceReader.ThrowIfNotEmpty();

            return new KrbFinished { GssMic = checksum };
        }

        /// <summary>
        /// Creates a KrbFinished with a checksum computed over the concatenated GSS-API tokens.
        /// </summary>
        public static KrbFinished Create(ReadOnlyMemory<byte> transcript, KerberosKey subkey)
        {
            if (subkey == null)
            {
                throw new ArgumentNullException(nameof(subkey));
            }

            var checksumType = CryptoService.ConvertType(subkey.EncryptionType);

            var checksum = CryptoService.CreateChecksum(checksumType, signatureData: transcript);
            checksum.Usage = KeyUsage.Finished;
            checksum.Sign(subkey);

            return new KrbFinished
            {
                GssMic = new KrbChecksum
                {
                    Checksum = checksum.Signature,
                    Type = checksumType
                }
            };
        }

        /// <summary>
        /// Verifies the KRB-FINISHED checksum against the transcript of exchanged tokens.
        /// Throws <see cref="System.Security.SecurityException"/> if verification fails.
        /// </summary>
        public void Verify(ReadOnlyMemory<byte> transcript, KerberosKey subkey)
        {
            if (subkey == null)
            {
                throw new ArgumentNullException(nameof(subkey));
            }

            var checksumType = this.GssMic.Type;

            var checksum = CryptoService.CreateChecksum(
                checksumType,
                signature: this.GssMic.Checksum,
                signatureData: transcript
            );
            checksum.Usage = KeyUsage.Finished;

            checksum.Validate(subkey);
        }
    }
}
