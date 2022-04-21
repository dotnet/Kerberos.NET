// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public interface IRealmService
    {
        /// <summary>
        /// The fully qualified name of the realm
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Global settings of the realm.
        /// </summary>
        IRealmSettings Settings { get; }

        /// <summary>
        /// The service used to query for all user and service principals.
        /// </summary>
        IPrincipalService Principals { get; }

        /// <summary>
        /// This realm may have one or more trust relationships to other realms.
        /// </summary>
        ITrustedRealmService TrustedRealms { get; }

        /// <summary>
        /// Provides access to the KDC configuration values.
        /// </summary>
        Krb5Config Configuration { get; }

        /// <summary>
        /// Returns the current time in UTC.
        /// </summary>
        /// <returns>Returns the current time in UTC</returns>
        DateTimeOffset Now();
    }

    public interface IPrincipalService
    {
        /// <summary>
        /// Find a user or service principal based on the provided <see cref="KrbPrincipalName" />
        /// </summary>
        /// <param name="principalName">The principal name to find</param>
        /// <param name="realm">Kerberos realm. Used to fully qualify principal name.</param>
        /// <returns>Returns <see cref="IKerberosPrincipal"/> that contains enough information to fulfill a Kerberos request</returns>
        IKerberosPrincipal Find(KrbPrincipalName principalName, string realm = null);

        /// <summary>
        /// Find a user or service principal based on the provided <see cref="KrbPrincipalName" />
        /// </summary>
        /// <param name="principalName">The principal name to find</param>
        /// <param name="realm">Kerberos realm. Used to fully qualify principal name.</param>
        /// <returns>Returns <see cref="IKerberosPrincipal"/> that contains enough information to fulfill a Kerberos request</returns>
        Task<IKerberosPrincipal> FindAsync(KrbPrincipalName principalName, string realm = null);

        /// <summary>
        /// Returns a server authentication certificate that can be used by the KDC to sign server messages.
        /// </summary>
        /// <returns>Returns an <see cref="X509Certificate2"/> containing a private key</returns>
        X509Certificate2 RetrieveKdcCertificate();

        /// <summary>
        /// Optionally look up a cached Diffie-Hellman server parameter for PKINIT
        /// </summary>
        /// <param name="algorithm">The algorithm of the cached key to retrieve</param>
        /// <returns>Returns an exchange key if found otherwise returns null</returns>
        IExchangeKey RetrieveKeyCache(KeyAgreementAlgorithm algorithm);

        /// <summary>
        /// Cache the server parameter exchange key used during PKINIT
        /// </summary>
        /// <param name="key">The key to cache</param>
        /// <returns>Returns the cached key</returns>
        IExchangeKey CacheKey(IExchangeKey key);
    }

    public interface IRealmSettings
    {
        /// <summary>
        /// The maximum window of time to add to a timestamp to determine validity.
        /// </summary>
        TimeSpan MaximumSkew { get; }

        /// <summary>
        /// The maximum lifetime of a service ticket before it needs to be renewed. Default is 10 hours.
        /// </summary>
        TimeSpan SessionLifetime { get; }

        /// <summary>
        /// The maximum length of time a ticket can be renewed if enabled. Default is 7 days.
        /// </summary>
        TimeSpan MaximumRenewalWindow { get; }

        /// <summary>
        /// Indicates the compatibility shims the KDC should enforce.
        /// </summary>
        KerberosCompatibilityFlags Compatibility { get; }
    }

    public interface IKerberosPrincipal
    {
        /// <summary>
        /// The fully-qualified principal name that will be used by the AS and TGS services.
        /// </summary>
        string PrincipalName { get; }

        /// <summary>
        /// The list of methods that can be used to authenticate the principal during an AS request.
        /// </summary>
        IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; }

        /// <summary>
        /// The list of cipher suites this principal has keys for and is willing to use during AS and TGS requests.
        /// </summary>
        SupportedEncryptionTypes SupportedEncryptionTypes { get; }

        /// <summary>
        /// Indicates the primary use of this principal object, such as being a user, service, or trust referral.
        /// </summary>
        PrincipalType Type { get; }

        /// <summary>
        /// Indicates when if ever this principal will expire and is used during PAC generation.
        /// </summary>
        DateTimeOffset? Expires { get; }

        /// <summary>
        /// Validates whether a certificate chain can correctly authenticate this user.
        /// Throws a <see cref="KerberosValidationException"/> if the certificate chain cannot be validated.
        /// </summary>
        /// <param name="certificates">The certificate chain for the user</param>
        void Validate(X509Certificate2Collection certificates);

        /// <summary>
        /// Retrieve the long term credentials used by the principal for authentication.
        /// In most cases it is their password-derived keys.
        /// </summary>
        /// <returns>Returns the expected long term key used during authentication</returns>
        KerberosKey RetrieveLongTermCredential();

        KerberosKey RetrieveLongTermCredential(EncryptionType etype);

        /// <summary>
        /// Generate the PAC used by Windows for authorization decisions.
        /// </summary>
        /// <returns>Returns a <see cref="PrivilegedAttributeCertificate"/> containing authorization data or null.</returns>
        PrivilegedAttributeCertificate GeneratePac();
    }
}
