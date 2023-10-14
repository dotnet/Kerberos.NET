using System;
using System.Buffers.Binary;

namespace Kerberos.NET.Entities.ChangePassword
{
    public class KrbChangePasswdReq
    {
        /*
         *       0                   1                   2                   3
         *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *      |         message length        |    protocol version number    |
         *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *      |          AP_REQ length        |         AP-REQ data           /
         *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *      /                         KRB-PRIV message                      /
         *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

        public KrbApReq ApReq { get; set; }
        public KrbPriv KrbPriv { get; set; }

        public KrbChangePasswdReq()
        {

        }
        
        public ReadOnlyMemory<byte> Encode()
        {
            var apReqBytes = ApReq.EncodeApplication();
            var krbPrivBytes = KrbPriv.EncodeApplication();

            /*
             *  0                   1                   2                   3
             *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *  |         message length        |    protocol version number    |
             *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *  |          AP_REQ length        |         AP_REQ data           /
             *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *  /                        KRB-PRIV message                       /
             *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             */

            // message length
            short messageLength = (short)(apReqBytes.Length + krbPrivBytes.Length + 6);

            var message = new Span<byte>(new byte[messageLength]);

            BinaryPrimitives.WriteInt16BigEndian(message.Slice(0, 2), messageLength);
            BinaryPrimitives.WriteInt16BigEndian(message.Slice(2, 2), -128); // version
            BinaryPrimitives.WriteInt16BigEndian(message.Slice(4, 2), (short)apReqBytes.Length);
            apReqBytes.Span.CopyTo(message.Slice(6, apReqBytes.Length));
            krbPrivBytes.Span.CopyTo(message.Slice(6 + apReqBytes.Length, krbPrivBytes.Length));

            return message.ToArray();
        }
               

    }


}
