using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Client
{
    public class ApplicationSessionContext
    {
        public KrbApReq ApReq { get; set; }

        public KrbEncryptionKey SessionKey { get; set; }

        public int? SequenceNumber { get; set; }

        public int CuSec { get; set; }

        public DateTimeOffset CTime { get; set; }

        public KrbEncryptionKey AuthenticateServiceResponse(string asRepEncoded)
        {
            var apRep = KrbApRep.DecodeApplication(Convert.FromBase64String(asRepEncoded));

            var decrypted = new DecryptedKrbApRep(apRep) { CTime = CTime, CuSec = CuSec, SequenceNumber = SequenceNumber };

            decrypted.Decrypt(SessionKey.AsKey());

            decrypted.Validate(ValidationActions.TokenWindow);

            return decrypted.Response.SubSessionKey ?? SessionKey;
        }
    }
}
