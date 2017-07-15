using System;
using System.Runtime.Serialization;

namespace Syfuhs.Security.Kerberos
{
    [Serializable]
    public class ReplayException : KerberosValidationException
    {
        public ReplayException() { }

        public ReplayException(string message)
            : base(message) { }

        public ReplayException(string message, Exception inner)
            : base(message, inner) { }

        protected ReplayException(SerializationInfo info, StreamingContext context)
            : base(info, context) { }
    }
}
