﻿using System.Linq;
using System.Text;

namespace Kerberos.NET.Crypto.AES
{
    internal static class AesSalts
    {
        public static string GenerateSalt(KerberosKey key)
        {
            if (!string.IsNullOrWhiteSpace(key.Salt))
            {
                return key.Salt;
            }

            var salt = new StringBuilder();

            GenerateSalt(key, salt);

            return salt.ToString();
        }

        public static void GenerateSalt(KerberosKey key, StringBuilder salt)
        {
            if (key.PrincipalName != null)
            {
                switch (key.SaltFormat)
                {
                    case SaltType.ActiveDirectoryService:
                        GenerateActiveDirectoryServiceSalt(key, salt);
                        break;
                    case SaltType.ActiveDirectoryUser:
                        GenerateActiveDirectoryUserSalt(key, salt);
                        break;
                    case SaltType.Rfc4120:
                        GenerateRfc4120Salt(key, salt);
                        break;
                }
            }
        }

        private static void GenerateRfc4120Salt(KerberosKey key, StringBuilder salt)
        {
            // RFC 4120 section 4
            // if none is provided via pre-authentication data, is the
            // concatenation of the principal's realm and name components, in order,
            // with no separators

            salt.Append(key.PrincipalName.Realm);

            foreach (var name in key.PrincipalName.Names)
            {
                salt.Append(name);
            }
        }

        private static void GenerateActiveDirectoryUserSalt(KerberosKey key, StringBuilder salt)
        {
            // User accounts: 
            //
            // < DNS of the realm, converted to upper case> | < user name >
            //
            // Ex: REALM.COMusername

            salt.Append(key.PrincipalName.Realm.ToUpperInvariant());
            salt.Append(key.PrincipalName.Names.First());
        }

        private static void GenerateActiveDirectoryServiceSalt(KerberosKey key, StringBuilder salt)
        {
            // Computer accounts: 
            //
            // < DNS name of the realm, converted to upper case > | 
            // "host" | 
            // < computer name, converted to lower case with trailing "$" stripped off > | 
            // "." | 
            // < DNS name of the realm, converted to lower case >
            //
            // Ex: REALM.COMhostappservice.realm.com

            salt.Append(key.PrincipalName.Realm.ToUpperInvariant());

            salt.Append("host");

            salt.Append(key.Host.ToLowerInvariant());
            salt.Append(".");
            salt.Append(key.PrincipalName.Realm.ToLowerInvariant());
        }
    }
}
