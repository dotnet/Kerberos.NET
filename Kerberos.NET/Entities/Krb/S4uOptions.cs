namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Options used during S4U logon for X509 Certificates.
    /// </summary>
    public enum S4uOptions
    {
        /// <summary>
        /// Requests the KDC to check logon hour restrictions.
        /// </summary>
        LogonHours = 0x40000000,

        /// <summary>
        /// Requests the KDC use KeyUsage number 27 when encrypting the response.
        /// </summary>
        UseReplyKeyUsage = 0x20000000
    }
}
