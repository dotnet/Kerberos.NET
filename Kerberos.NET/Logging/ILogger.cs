using System;

namespace Kerberos.NET
{
    public enum KerberosLogSource
    {
        Authenticator,
        Validator,
        ReplayCache
    }

    public interface ILogger
    {
        bool Enabled { get; set; }

        void WriteLine(KerberosLogSource source, string value);

        void WriteLine(KerberosLogSource source, string value, Exception ex);
    }
}
