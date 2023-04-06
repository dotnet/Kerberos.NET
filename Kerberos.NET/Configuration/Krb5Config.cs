// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;

namespace Kerberos.NET.Configuration
{
    /// <summary>
    /// Krb5 configuration for Kerberos client, server, and KDC behaviors. These configuration elements are in sync with
    /// MIT Krb5 1.18: https://web.mit.edu/kerberos/krb5-1.18/doc/admin/conf_files/krb5_conf.html.
    /// </summary>
    public class Krb5Config
    {
        public Krb5Config()
        {
            ConfigurationSectionList.Default.ToConfigObject(this);
        }

        /// <summary>
        /// System defaults that will be used if the protocol or client do not provide explicit values.
        /// </summary>
        [DisplayName("libdefaults")]
        public Krb5ConfigDefaults Defaults { get; private set; }

        /// <summary>
        /// System defaults that will be used by the KDC implementation.
        /// </summary>
        [DisplayName("kdcdefaults")]
        public Krb5KdcDefaults KdcDefaults { get; private set; }

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

        public static string UserConfigurationPath => GetFilePath(
            envVar: "%KRB5_CONFIG%",
            winPath: "%APPDATA%\\Kerberos.NET\\",
            osxPath: "Library/Preferences/Kerberos.NET/",
            linuxPath: "/etc/"
        );

        public static string ServiceConfigurationPath => GetFilePath(
            envVar: "%KRB5_KDC_PROFILE%",
            winPath: "%APPDATA%\\Kerberos.NET\\",
            osxPath: "Library/Preferences/Kerberos.NET/",
            linuxPath: "/var/krb5kdc"
        );

        public static string DefaultUserConfigurationPath => Path.Combine(UserConfigurationPath, "krb5.conf");

        public static string DefaultUserCredentialCachePath => Path.Combine(UserConfigurationPath, ".krb5cc");

        public static string DefaultKdcConfigurationPath => Path.Combine(ServiceConfigurationPath, "kdc.conf");

        public static Krb5Config Parse(string config) => Krb5ConfigurationSerializer.Deserialize(config).ToConfigObject();

        public static Krb5Config Kdc(string path = null)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                path = DefaultKdcConfigurationPath;
            }

            if (File.Exists(path))
            {
                return Krb5ConfigurationSerializer.Deserialize(File.ReadAllText(path)).ToConfigObject();
            }

            return Default();
        }

        public static Krb5Config CurrentUser(string path = null)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                path = DefaultUserConfigurationPath;
            }

            if (File.Exists(path))
            {
                return Krb5ConfigurationSerializer.Deserialize(File.ReadAllText(path)).ToConfigObject();
            }

            return Default();
        }

        public static Krb5Config Default() => new Krb5Config();

        public string Serialize() => this.Serialize(null);

        public string Serialize(Krb5ConfigurationSerializationConfig serializationConfig) => Krb5ConfigurationSerializer.Serialize(this, serializationConfig);

        public bool TryFindRealmHint(string spn, out string referral)
        {
            foreach (var kv in this.DomainRealm)
            {
                //
                // .foo.net matches anything under foo.net
                //      bar.foo.net matches
                //      baz.foo.net matches
                //      baz.bar.foo.net matches
                //      foo.net does not match
                //      bar.net does not match
                //
                // bar.foo.net matches explicitly
                //      bar.foo.net matches
                //      baz.foo.net does not match
                //      baz.bar.foo.net does not match
                //      foo.net does not match
                //

                if ((kv.Key[0] == '.' && spn.EndsWith(kv.Key, StringComparison.OrdinalIgnoreCase)) ||
                    (string.Equals(kv.Key, spn, StringComparison.InvariantCultureIgnoreCase)))
                {
                    referral = kv.Value.ToUpperInvariant();
                    return true;
                }
            }

            referral = null;
            return false;
        }

        private static string GetFilePath(string envVar, string winPath, string osxPath, string linuxPath)
        {
            var config = Environment.ExpandEnvironmentVariables(envVar);

            if (!string.IsNullOrWhiteSpace(config) && !envVar.Equals(config, StringComparison.Ordinal))
            {
                return config;
            }
            else if (OSPlatform.IsWindows)
            {
                return Environment.ExpandEnvironmentVariables(winPath);
            }
            else if (OSPlatform.IsOsX)
            {
                return osxPath;
            }
            else if (OSPlatform.IsLinux)
            {
                return linuxPath;
            }

            return string.Empty;
        }
    }
}
