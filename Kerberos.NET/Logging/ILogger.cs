using System;

namespace Kerberos.NET
{
    public enum KerberosLogSource
    {
        Authenticator,
        Validator,
        Cache,
        Client,
        ServiceListener,
        Kdc
    }

    public enum LogLevel
    {
        Error = 0,
        Warning = 1,
        Information = 2,
        Verbose = 3,
        Debug = 4
    }

    public interface ILogger
    {
        LogLevel Level { get; set; }

        bool Enabled { get; set; }

        void WriteLine(KerberosLogSource source, string value);

        void WriteLine(KerberosLogSource source, Exception ex);

        void WriteLine(KerberosLogSource source, string value, Exception ex);
    }
}
