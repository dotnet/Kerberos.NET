using Kerberos.NET.Asn1;
using System;
using System.Collections.Generic;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class KrbAsReq : KrbKdcReq
    {
        public KrbAsReq() { }

        /*
        
        AS-REQ          ::= [APPLICATION 10] KDC-REQ
 
        */

        public KrbAsReq Decode(Asn1Element element)
        {
            return Decode<KrbAsReq>(element);
        }
    }
}
