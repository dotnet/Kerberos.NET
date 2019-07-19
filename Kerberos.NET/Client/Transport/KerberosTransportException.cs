using Kerberos.NET.Client;
using Kerberos.NET.Entities;
using System;
using System.Runtime.Serialization;

namespace Kerberos.NET.Transport
{

    [Serializable]
    public class KerberosTransportException : KerberosProtocolException
    {
        public KerberosTransportException() { }

        public KerberosTransportException(KrbError error)
            : base(error)
        { }

        public KerberosTransportException(string message) : base(message) { }

        public KerberosTransportException(string message, Exception inner)
            : base(message, inner) { }

        protected KerberosTransportException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}
