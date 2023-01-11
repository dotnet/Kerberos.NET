namespace Kerberos.NET.Configuration
{
    /// <summary>
    /// Possible values for <see cref="Krb5ConfigDefaults.DnsCanonicalizeHostname"/>
    /// </summary>
    public enum DnsCanonicalization
    {
        /// <summary>
        /// Canonicalization disabled.
        /// </summary>
        False,

        /// <summary>
        /// Canonicalization enabled.
        /// </summary>
        True,

        /// <summary>
        /// DNS canonicalization will only be performed the server hostname is not found with the original name when requesting credentials.
        /// </summary>
        Fallback
    }
}
