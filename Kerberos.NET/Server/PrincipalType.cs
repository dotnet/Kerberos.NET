namespace Kerberos.NET.Server
{
    public enum PrincipalType
    {
        /// <summary>
        /// Indicates the principal is a regular user that can authenticate and request service tickets
        /// </summary>
        User = 0,

        /// <summary>
        /// Indicates the principal is a service that can receive service tickets from other users
        /// </summary>
        Service,

        /// <summary>
        /// Indicates the principal is actually a partner realm and needs to be referred before the request can be completed
        /// </summary>
        TrustedDomain
    }
}
