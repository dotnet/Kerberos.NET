using System;
using System.Security;

namespace Kerberos.NET
{
    [Serializable]
    public class KerberosValidationException : SecurityException
    {
        public KerberosValidationException(string message, string parameter = null)
            : base(message)
        {
            this.Parameter = parameter;
        }

        public KerberosValidationException(string message, Exception inner)
            : base(message, inner) { }

        public string Parameter { get; }
    }
}
