using System;
using System.Runtime.Serialization;
using System.Security;

namespace Kerberos.NET
{
    [Serializable]
    public class KerberosValidationException : SecurityException
    {
        public KerberosValidationException() { }

        public KerberosValidationException(string message)
            : base(message) { }

        public KerberosValidationException(string message, Exception inner)
            : base(message, inner) { }

        protected KerberosValidationException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}
