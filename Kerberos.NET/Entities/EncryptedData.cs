using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public class EncryptedData
    {
        public EncryptedData(Asn1Element element)
        {
            var childNode = element[0];

            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        EType = (EncryptionType)node[0].AsInt();
                        break;

                    case 1:
                        KeyVersionNumber = node[0].AsInt();
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

        public int? KeyVersionNumber { get; private set; }

        public byte[] Cipher { get; private set; }
    }
}
