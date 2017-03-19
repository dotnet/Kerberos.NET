using Syfuhs.Security.Kerberos.Crypto;
using System;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class EncryptedData : Asn1ValueType
    {
        public EncryptedData(Asn1Element asn1Element)
        {
            Asn1Value = asn1Element.Value;

            Asn1Element childNode = asn1Element[0];

            for (int i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        EType = (EncryptionType)((int)node[0].AsLong());
                        break;

                    case 1:
                        KeyVersionNumber = (uint)node[0].AsLong();
                        break;

                    case 2:
                        var cipherNode = node[0];

                        Cipher = new byte[cipherNode.Length];

                        Buffer.BlockCopy(cipherNode.Value, 0, Cipher, 0, Cipher.Length);
                        break;
                }
            }
        }

        public EncryptionType EType { get; private set; }

        public uint? KeyVersionNumber { get; private set; }

        public byte[] Cipher { get; private set; }
    }
}
