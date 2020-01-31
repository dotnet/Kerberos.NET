using System;

namespace Kerberos.NET
{
    [Serializable]
    public class ReplayException : KerberosValidationException
    {
        public ReplayException(string message)
            : base(message) { }
    }
}
