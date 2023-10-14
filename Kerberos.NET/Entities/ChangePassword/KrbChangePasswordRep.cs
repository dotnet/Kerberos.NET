using Kerberos.NET.Crypto;
using System;
using System.Buffers.Binary;
using System.IO;

namespace Kerberos.NET.Entities.ChangePassword
{
    public class KrbChangePasswdRep
    {
        /*
         *       0                   1                   2                   3
         *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *      |         message length        |    protocol version number    |
         *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *      |          AP_REP length        |         AP-REP data           /
         *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *      /                         KRB-PRIV message                      /
         *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

        /* UserData of KRB-PRIV:
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |          result code          |        result string          /
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        */

        public KrbApRep ApRep { get; private set; }

        public KrbPriv KrbPriv { get; private set; }

        public KrbEncKrbPrivPart encKrbPriv { get; private set; }

        public enum StatusCode
        {
            KRB5_KPASSWD_SUCCESS = 0,             // request succeeds (This value is not allowed in a KRB-ERROR message)
            KRB5_KPASSWD_MALFORMED = 1,           // request fails due to being malformed
            KRB5_KPASSWD_HARDERROR = 2,           // request fails due to "hard" error in processing the request(for example, there is a resource or other problem causing the request to fail)
            KRB5_KPASSWD_AUTHERROR = 3,           // request fails due to an error in authentication processing
            KRB5_KPASSWD_SOFTERROR = 4,           // request fails due to a "soft" error in processing the request
            KRB5_KPASSWD_ACCESSDENIED = 5,        // requestor not authorized
            KRB5_KPASSWD_BAD_VERSION = 6,         // protocol version unsupported
            KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7, // initial flag required
            KRB5_KPASSWD_OTHER = 0xFFFF           // returned if the request fails for some other reason.
        };

        public KrbChangePasswdRep(ReadOnlyMemory<byte> data)
        {
            Decode(data);
        }

        private void Decode(ReadOnlyMemory<byte> data)
        {
            if (data.Length < 6)
            {
                throw new InvalidDataException("KrbChangePassword message too short");
            }

            short messageLength = BinaryPrimitives.ReadInt16BigEndian(data.Span.Slice(0, 2));
            if (data.Length < messageLength)
            {
                throw new InvalidDataException("KrbChangePassword message shorter than message length header says");
            }

            short version = BinaryPrimitives.ReadInt16BigEndian(data.Span.Slice(2, 2));
            if (version != 1)
            {
                throw new InvalidDataException("KrbChangePassword bad version in reply");
            }

            short apRepLength = BinaryPrimitives.ReadInt16BigEndian(data.Span.Slice(4, 2));
            if (apRepLength + 6 > messageLength)
            {
                throw new InvalidDataException("KrbChangePassword apRepLength too long");
            }

            ApRep = KrbApRep.DecodeApplication(data.Span.Slice(6, apRepLength).ToArray());

            short krbPrivLength = (short)(messageLength - apRepLength - 6);
            if (krbPrivLength <= 2) // krbPriv is ASN encoded
            {
                throw new InvalidDataException("KrbChangePassword krbPriv remaining length too short");
            }

            KrbPriv = KrbPriv.DecodeApplication(data.Span.Slice(6 + apRepLength, krbPrivLength).ToArray());
        }

        public void Decrypt(KerberosKey key)
        {           
            encKrbPriv = KrbPriv.EncPart.Decrypt(
                key,
                KeyUsage.EncKrbPrivPart,
                d => KrbEncKrbPrivPart.DecodeApplication(d)
            );
        }

    }


}
