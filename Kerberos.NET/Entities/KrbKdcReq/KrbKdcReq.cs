using Kerberos.NET.Asn1;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    public class KrbKdcReq
    {
        public KrbKdcReq() { }

        public int ProtocolVersionNumber { get; set; }

        public MessageType MessageType { get; set; }

        public IEnumerable<KrbPaData> PaData { get; set; }

        public KrbKdcReqBody Body { get; set; }

        /*

        KDC-REQ         ::= SEQUENCE {
                -- NOTE: first tag is [1], not [0]
                pvno            [1] INTEGER (5) ,
                msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
                padata          [3] SEQUENCE OF PA-DATA OPTIONAL
                                    -- NOTE: not empty --,
                req-body        [4] KDC-REQ-BODY
        }

        */

        public virtual T Decode<T>(Asn1Element element)
            where T : KrbKdcReq, new()
        {
            var req = this;

            for (var i = 0; i < element.Count; i++)
            {
                var child = element[i];

                switch (child.ContextSpecificTag)
                {
                    case 1:
                        req.ProtocolVersionNumber = child[0].AsInt();
                        break;
                    case 2:
                        req.MessageType = (MessageType)child[0].AsLong();
                        break;
                    case 3:
                        req.PaData = DecodePaData(child[0]);
                        break;
                    case 4:
                        req.Body = new KrbKdcReqBody().Decode(child[0]);
                        break;
                }
            }

            return (T)req;
        }

        private IEnumerable<KrbPaData> DecodePaData(Asn1Element element)
        {
            var list = new List<KrbPaData>();

            for (var i = 0; i < element.Count; i++)
            {
                list.Add(new KrbPaData().Decode(element[i]));
            }

            return list;
        }
    }
}
