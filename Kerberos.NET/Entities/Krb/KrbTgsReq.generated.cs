// This is a generated file.
// This file is licensed as per the LICENSE file.
// The generation template has been modified from .NET Foundation implementation
using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsReq : KrbKdcReq
    {
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 12);
        
        public ReadOnlyMemory<byte> EncodeApplication() 
        {
          return EncodeApplication(ApplicationTag);
        }
        
        public static KrbTgsReq DecodeApplication(ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var sequence = reader.ReadSequence(ApplicationTag);
          
            KrbTgsReq decoded;
            Decode(sequence, out decoded);
            sequence.ThrowIfNotEmpty();

            reader.ThrowIfNotEmpty();

            return decoded;
        }
             
    }
}
  