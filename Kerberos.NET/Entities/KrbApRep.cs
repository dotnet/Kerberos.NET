using Kerberos.NET.Crypto;
using System;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Entities
{
    //[ExpectedTag(System.Security.Cryptography.Asn1.TagClass.Application, 15)]
    [StructLayout(LayoutKind.Sequential)]
    public sealed class KrbApRep
    {
        public const int ApplicationTag = 15;

        public KrbApRep() { }

        public KrbApRep(Asn1Element sequence)
        {
            for (var i = 0; i < sequence.Count; i++)
            {
                var element = sequence[i];

                switch (element.ContextSpecificTag)
                {
                    case 0:
                        VersionNumber = element[0].AsInt();
                        break;
                    case 1:
                        MessageType = (MessageType)element[0].AsInt();
                        break;
                    case 2:
                        EncPart = new EncryptedData(element);
                        break;
                }
            }
        }

        [Tag(0)]
        public int VersionNumber;

        [Tag(1)]
        public MessageType MessageType;

        [Tag(2)]
        public EncryptedData EncPart;

        public const KeyUsage EncPartKeyUsage = KeyUsage.KU_ENC_AP_REP_PART;
    }

    [Tag(27, System.Security.Cryptography.Asn1.TagClass.Application)]
    public class EncAPRepPart
    {
        [Tag(0)]
        public DateTimeOffset CTime;

        [Tag(1)]
        public long CuSec;

        [Tag(2), OptionalValue]
        public EncryptionKey SubKey;

        [Tag(3), OptionalValue]
        public int SequenceNumber;
    }
}