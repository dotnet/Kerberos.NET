using System;
using System.Security;

namespace Kerberos.NET
{
    [Serializable]
    public class KerberosValidationException : SecurityException
    {
        public KerberosValidationException(string message)
            : base(message) { }

        public KerberosValidationException(string message, Exception inner)
            : base(message, inner) { }
    }
}
