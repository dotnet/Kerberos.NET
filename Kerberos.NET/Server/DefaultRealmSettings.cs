using System;
using Kerberos.NET.Configuration;

namespace Kerberos.NET.Server
{
    /// <summary>
    /// A simple implementation of the realm settings that wraps KRB5 configuration.
    /// </summary>
    public class DefaultRealmSettings : IRealmSettings
    {
        private readonly Krb5ConfigDefaults defaults;
        private readonly Krb5RealmConfig config;
        private readonly KerberosCompatibilityFlags compatibilityFlags;

        public DefaultRealmSettings(Krb5ConfigDefaults defaults, Krb5RealmConfig config)
            : this(defaults, config, KerberosCompatibilityFlags.None)
        {
        }

        public DefaultRealmSettings(
            Krb5ConfigDefaults defaults,
            Krb5RealmConfig config,
            KerberosCompatibilityFlags compatibilityFlags)
        {
            this.defaults = defaults;
            this.config = config;
            this.compatibilityFlags = compatibilityFlags;
        }

        /// <inheritdoc />
        public TimeSpan MaximumSkew => this.defaults.ClockSkew;

        /// <inheritdoc />
        public TimeSpan SessionLifetime => this.config.KdcMaxTicketLifetime;

        /// <inheritdoc />
        public TimeSpan MaximumRenewalWindow => this.config.KdcMaxRenewableLifetime;

        /// <inheritdoc />
        public KerberosCompatibilityFlags Compatibility => this.compatibilityFlags;
    }
}
