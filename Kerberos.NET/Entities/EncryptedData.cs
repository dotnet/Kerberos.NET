using Kerberos.NET.Crypto;
using System.Runtime.InteropServices;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public sealed class EncryptedData
    {
        public EncryptedData Decode(Asn1Element element)
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
                        Cipher = node[0].BlockCopy();
                        break;
                }
            }

            return this;
        }

        //[ExpectedTag(0)]
        public EncryptionType EType;

        //[ExpectedTag(1), OptionalValue]
        public int? KeyVersionNumber;

        //[ExpectedTag(2)]
        public byte[] Cipher;
    }
}
