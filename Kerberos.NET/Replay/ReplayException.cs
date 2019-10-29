using System;

namespace Kerberos.NET
{
    public class ReplayException : KerberosValidationException
    {
        public ReplayException(string message)
            : base(message) { }
    }
}
