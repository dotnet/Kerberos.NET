// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.ComponentModel;

namespace Kerberos.NET.Configuration
{
    /// <summary>
    /// Krb5 configuration for Kerberos client, server, and KDC behaviors. These configuration elements are in sync with
    /// MIT Krb5 1.18: https://web.mit.edu/kerberos/krb5-1.18/doc/admin/conf_files/krb5_conf.html.
    /// </summary>
    public class Krb5Config
    {
        /// <summary>
        /// System defaults that will be used if the protocol or client do not provide explicit values.
        /// </summary>
        [DisplayName("libdefaults")]
        public Krb5ConfigDefaults Defaults { get; private set; }

        /// <summary>
        /// A mapping of realm names to their respective settings. Note that realm
        /// names are case sensitive and most environments use UPPERCASE realm names.
        /// </summary>
        [DisplayName("realms")]
        public IDictionary<string, Krb5RealmConfig> Realms { get; private set; }

        /// <summary>
        /// Provides a translation from a domain name or hostname to a Kerberos realm name. The key can be a host name
        /// or domain name, where domain names are indicated by a prefix of a period (.). The value of the relation is the
        /// Kerberos realm name for that particular host or domain. A host name relation implicitly provides the corresponding
        /// domain name relation, unless an explicit domain name relation is provided.
        /// [hostname.domainname.com] = "KERBEROS.REALM.COM"
        /// </summary>
        [DisplayName("domain_realm")]
        public IDictionary<string, string> DomainRealm { get; private set; }

        /// <summary>
        /// A client will use this section to find the authentication path between its realm and the realm of the server.
        /// The server will use this section to verify the authentication path used by the client.
        ///
        /// There is a key for each participating client realm, and each key has mappings for each of the server realms.
        /// The value of the map is an intermediate realm which may participate in the cross-realm authentication.
        /// A value of "." means that the two realms share keys directly, and no intermediate realms should be allowed to participate.
        /// </summary>
        [DisplayName("capaths")]
        public IDictionary<string, IDictionary<string, string>> CaPaths { get; private set; }

        /// <summary>
        /// Provides a collection of settings that can be applied to services.
        /// </summary>
        [DisplayName("appdefaults")]
        public ConfigurationSectionList AppDefaults { get; private set; }

        /// <summary>
        /// Provides logging configuration settings.
        /// </summary>
        [DisplayName("logging")]
        public Krb5Logging Logging { get; private set; }

        public static Krb5Config Default()
        {
            return Krb5ConfigurationSerializer.Deserialize(string.Empty).ToConfigObject();
        }

        public string Serialize()
        {
            return Krb5ConfigurationSerializer.Serialize(this);
        }
    }
}
