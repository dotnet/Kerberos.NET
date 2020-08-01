namespace Kerberos.NET.Configuration
{
    /// <summary>
    /// The the methods used to verify if a certificate contains the necessary EKUs.
    /// </summary>
    public enum PkInitEkuCheck
    {
        /// <summary>
        /// This is the default value and specifies that the KDC must have the id-pkinit-KPKdc EKU as defined in RFC 4556.
        /// </summary>
        KpKdc,

        /// <summary>
        /// If kpServerAuth is specified, a KDC certificate with the id-kp-serverAuth EKU will be accepted.
        /// This key usage value is used in most commercially issued server certificates.
        /// </summary>
        KpServerAuth,

        /// <summary>
        /// If none is specified, then the KDC certificate will not be checked to verify it has an acceptable EKU.
        /// </summary>
        None,
    }
}
