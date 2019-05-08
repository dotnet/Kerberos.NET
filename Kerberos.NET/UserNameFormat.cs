namespace Kerberos.NET
{
    /// <summary>
    /// Specifies the credentials format 
    /// </summary>
    public enum UserNameFormat
    {
        /// <summary>
        /// User principal name (UPN) format is used to specify an Internet-style name in format such as user@REALM.COM
        /// </summary>
        UserPrincipalName,
        /// <summary>
        /// The down-level logon name format is used to specify a domain and a user account in that domain, such as DOMAIN\UserName
        /// </summary>
        DownLevelLogonName
    }
}