// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Configuration
{
    public class Krb5ConfigDefaults : Krb5ConfigObject
    {
        /// <summary>
        /// If this flag is set to false, then weak encryption types will be filtered out of the lists
        /// default_tgs_enctypes, default_tkt_enctypes, and permitted_enctypes. The default value for this tag is false.
        /// </summary>
        [DisplayName("allow_weak_crypto")]
        public bool AllowWeakCrypto { get; set; }

        /// <summary>
        /// If this flag is set to true, initial ticket requests to the KDC will request canonicalization of the client
        /// principal name, and answers with different client principals than the requested principal will be accepted.
        /// The default value is true.
        /// </summary>
        [DefaultValue(true)]
        [DisplayName("canonicalize")]
        public bool Canonicalize { get; set; } = true;

        /// <summary>
        /// This parameter determines the format of credential cache types created by kinit or other programs.
        /// The default value is 4, which represents the most current format. Smaller values can be used for
        /// compatibility with very old implementations of Kerberos which interact with credential caches on the same host.
        /// </summary>
        [DefaultValue(4)]
        [DisplayName("ccache_type")]
        public int CCacheType { get; set; }

        /// <summary>
        /// Sets the maximum allowable amount of clockskew in seconds that the library will tolerate before assuming that
        /// a Kerberos message is invalid. The default value is 300 seconds, or five minutes. The clockskew setting is also
        /// used when evaluating ticket start and expiration times. For example, tickets that have reached their expiration
        /// time can still be used if they have been expired for a shorter duration than the clockskew setting.
        /// </summary>
        [DefaultValue(300)]
        [DisplayName("clockskew")]
        public int ClockSkew { get; set; }

        /// <summary>
        /// This relation specifies the name of the default credential cache. The default is "FILE:%APPDATA%\Kerberos.NET\.krb5cc".
        /// </summary>
        [DefaultValue("FILE:%APPDATA%\\Kerberos.NET\\.krb5cc")]
        [DisplayName("default_ccache_name")]
        public string DefaultCCacheName { get; set; }

        /// <summary>
        /// This relation specifies the name of the default keytab for obtaining client credentials. The default is %DEFCKTNAME%.
        /// </summary>
        [DefaultValue("%DEFCKTNAME%")]
        [DisplayName("default_client_keytab_name")]
        public string DefaultClientKeytabName { get; set; }

        /// <summary>
        /// This relation specifies the default keytab name to be used by application servers such as sshd. The default is %DEFKTNAME%.
        /// </summary>
        [DefaultValue("%DEFKTNAME%")]
        [DisplayName("default_keytab_name")]
        public string DefaultKeytabName { get; set; }

        /// <summary>
        /// This relation specifies the name of the default replay cache. The default is dfl:.
        /// </summary>
        [DefaultValue("dfl:")]
        [DisplayName("default_rcache_name")]
        public string DefaultReplayCacheName { get; set; }

        /// <summary>
        /// Identifies the default Kerberos realm for the client. Set its value to your Kerberos realm.
        /// If this value is not set, then a realm must be specified with every Kerberos principal.
        /// </summary>
        [DisplayName("default_realm")]
        public string DefaultRealm { get; set; }

        /// <summary>
        /// Identifies the supported list of session key encryption types that the client should
        /// request when making a TGS-REQ, in order of preference from highest to lowest. The
        /// list may be delimited with commas or whitespace.
        /// </summary>
        [DefaultValue("aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac-nt")]
        [DisplayName("default_tgs_enctypes")]
        public ICollection<EncryptionType> DefaultTgsEncTypes { get; private set; }

        /// <summary>
        /// Identifies the supported list of session key encryption types that the client should
        /// request when making an AS-REQ, in order of preference from highest to lowest. The format
        /// is the same as for default_tgs_enctypes.
        /// </summary>
        [DefaultValue("aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac-nt")]
        [DisplayName("default_tkt_enctypes")]
        public ICollection<EncryptionType> DefaultTicketEncTypes { get; private set;  }

        /// <summary>
        /// Indicate whether name lookups will be used to canonicalize hostnames for use in service
        /// principal names. Setting this flag to false can improve security by reducing reliance on
        /// DNS, but means that short hostnames will not be canonicalized to fully-qualified hostnames.
        /// The default value is false.
        /// </summary>
        [DefaultValue(false)]
        [DisplayName("dns_canonicalize_hostname")]
        public bool DnsCanonicalizeHostname { get; set; }

        /// <summary>
        /// Indicate whether DNS SRV records should be used to locate the KDCs and other servers for a realm,
        /// if they are not listed in the krb5.conf information for the realm.
        /// </summary>
        [DefaultValue(true)]
        [DisplayName("dns_lookup_kdc")]
        public bool DnsLookupKdc { get; set; }

        /// <summary>
        /// Indicate whether DNS URI records should be used to locate the KDCs and other servers for a realm,
        /// if they are not listed in the krb5.conf information for the realm. SRV records are used as a fallback
        /// if no URI records were found.
        /// </summary>
        [DefaultValue(true)]
        [DisplayName("dns_uri_lookup")]
        public bool DnsUriLookup { get; set; }

        /// <summary>
        /// If this flag to true, GSSAPI credential delegation will be disabled when the ok-as-delegate flag is not
        /// set in the service ticket. If this flag is false, the ok-as-delegate ticket flag is only enforced when
        /// an application specifically requests enforcement. The default value is false.
        /// </summary>
        [DefaultValue(false)]
        [DisplayName("enforce_ok_as_delegate")]
        public bool EnforceOkAsDelegate { get; set; }

        /// <summary>
        /// This allows a computer to use multiple local addresses, in order to allow Kerberos to work in a network that uses NATs
        /// while still using address-restricted tickets. The addresses should be in a comma-separated list. This option has no
        /// effect if noaddresses is true.
        /// </summary>
        [CommaSeparatedList]
        [DisplayName("extra_addresses")]
        public ICollection<string> ExtraAddresses { get; private set;  }

        /// <summary>
        /// If this flag is true, initial tickets will be forwardable by default, if allowed by the KDC. The default value is false.
        /// </summary>
        [DisplayName("forwardable")]
        public bool Forwardable { get; set; }

        /// <summary>
        /// When accepting GSSAPI or krb5 security contexts for host-based service principals, ignore any hostname passed by the
        /// calling application, and allow clients to authenticate to any service principal in the keytab matching the service
        /// name and realm name.
        /// </summary>
        [DefaultValue(true)]
        [DisplayName("ignore_acceptor_hostname")]
        public bool IgnoreAcceptorHostname { get; set; }

        /// <summary>
        /// If this flag is true, principals must be listed in a local user’s k5login file to be granted login access, if a .k5login
        /// file exists. If this flag is false, a principal may still be granted login access through other mechanisms even if a k5login
        /// file exists but does not list the principal. The default value is true.
        /// </summary>
        [DisplayName("k5login_authoritative")]
        public bool K5LoginAuthoritative { get; set; }

        /// <summary>
        /// If set, the library will look for a local user’s k5login file within the named directory, with a filename corresponding to the
        /// local username. If not set, the library will look for k5login files in the user’s home directory, with the filename .k5login.
        /// </summary>
        [DisplayName("k5login_directory")]
        public string K5LoginDirectory { get; set; }

        /// <summary>
        /// On macOS only, determines the name of the bootstrap service used to contact the KCM daemon for the KCM credential cache type.
        /// If the value is -, Mach RPC will not be used to contact the KCM daemon. The default value is org.h5l.kcm.
        /// </summary>
        [DefaultValue("org.h5l.kcm")]
        [DisplayName("kcm_mach_service")]
        public string KcmMachService { get; set; }

        /// <summary>
        /// Determines the path to the Unix domain socket used to access the KCM daemon for the KCM credential cache type. If the value is -,
        /// Unix domain sockets will not be used to contact the KCM daemon. The default value is /var/run/.heim_org.h5l.kcm-socket.
        /// </summary>
        [DefaultValue("/var/run/.heim_org.h5l.kcm-socket")]
        [DisplayName("kcm_socket")]
        public string KcmSocket { get; set; }

        /// <summary>
        /// Default KDC options (Xored for multiple values) when requesting initial tickets. By default it is set to 0x00000010 (KDC_OPT_RENEWABLE_OK).
        /// </summary>
        [EnumAsInteger]
        [DefaultValue(KdcOptions.RenewableOk)]
        [DisplayName("kdc_default_options")]
        public KdcOptions KdcDefaultOptions { get; set; }

        /// <summary>
        /// Accepted values for this relation are 1 or 0. If it is nonzero, client machines will compute the difference between their time and
        /// the time returned by the KDC in the timestamps in the tickets and use this value to correct for an inaccurate system clock when requesting
        /// service tickets or authenticating to services. This corrective factor is only used by the Kerberos library; it is not used to change the
        /// system clock. The default value is 1.
        /// </summary>
        [DefaultValue(1)]
        [DisplayName("kdc_timesync")]
        public int KdcTimeSync { get; set; }

        /// <summary>
        /// If this flag is true, requests for initial tickets will not be made with address restrictions set, allowing the tickets to be
        /// used across NATs. The default value is true.
        /// </summary>
        [DefaultValue(true)]
        [DisplayName("noaddresses")]
        public bool NoAddresses { get; set; }

        /// <summary>
        /// Identifies the encryption types that servers will permit for session keys and for ticket and authenticator encryption,
        /// ordered by preference from highest to lowest. Starting in release 1.18, this tag also acts as the default value for
        /// default_tgs_enctypes and default_tkt_enctypes.
        /// </summary>
        [DefaultValue("aes128-cts-hmac-sha256-128 aes256-cts-hmac-sha384-192 aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac-nt")]
        [DisplayName("permitted_enctypes")]
        public ICollection<EncryptionType> PermittedEncryptionTypes { get; private set;  }

        /// <summary>
        /// If set, determines the base directory where krb5 plugins are located.
        /// </summary>
        [DisplayName("plugin_base_dir")]
        public string PluginBaseDirectory { get; set; }

        /// <summary>
        /// This allows you to set the preferred preauthentication types which the client will attempt before others which
        /// may be advertised by a KDC. The default value for this setting is “17, 16, 2”, which forces the library
        /// to attempt to use PKINIT if it is supported.
        /// </summary>
        [CommaSeparatedList]
        [DefaultValue("17,16,2")]
        [DisplayName("preferred_preauth_types")]
        public ICollection<PaDataType> PreferredPreAuthTypes { get; private set;  }

        /// <summary>
        /// If this flag is true, initial tickets will be proxiable by default, if allowed by the KDC. The default value is false.
        /// </summary>
        [DisplayName("proxiable")]
        public bool Proxiable { get; set; }

        /// <summary>
        /// If this string is set, it determines the domain suffix for single-component hostnames when DNS canonicalization
        /// is not used (either because dns_canonicalize_hostname is false or because forward canonicalization failed).
        /// The default value is the first search domain of the system’s DNS configuration.
        /// </summary>
        [DisplayName("qualify_shortname")]
        public string QualifyShortname { get; set; }

        /// <summary>
        /// If this flag is true, reverse name lookup will be used in addition to forward name lookup to canonicalizing
        /// hostnames for use in service principal names. If dns_canonicalize_hostname is set to false, this flag has no
        /// effect. The default value is false.
        /// </summary>
        [DisplayName("rdns")]
        public bool RDNS { get; set; }

        /// <summary>
        /// Indicate whether a host’s domain components should be used to determine the Kerberos realm of the host. The value
        /// of this variable is an integer: -1 means not to search, 0 means to try the host’s domain itself, 1 means to also
        /// try the domain’s immediate parent, and so forth. The library’s usual mechanism for locating Kerberos realms is used
        /// to determine whether a domain is a valid realm, which may involve consulting DNS if dns_lookup_kdc is set. The default
        /// is not to search domain components.
        /// </summary>
        [DefaultValue(-1)]
        [DisplayName("realm_try_domains")]
        public int RealmTryDomains { get; set; }

        /// <summary>
        /// Sets the default renewable lifetime for initial ticket requests. The default value is 0.
        /// </summary>
        [DefaultValue("0")]
        [DisplayName("renew_lifetime")]
        public TimeSpan RenewLifetime { get; set; }

        /// <summary>
        /// A whitespace or comma-separated list of words which specifies the groups allowed for SPAKE preauthentication.
        /// </summary>
        [DisplayName("spake_preauth_groups")]
        public ICollection<string> SpakePreAuthGroups { get; private set;  }

        /// <summary>
        /// Sets the default lifetime for initial ticket requests. The default value is 1 day.
        /// </summary>
        [DefaultValue("1d")]
        [DisplayName("ticket_lifetime")]
        public TimeSpan TicketLifetime { get; set; }

        /// <summary>
        /// When sending a message to the KDC, the library will try using TCP before UDP if the size of the message is above
        /// udp_preference_limit. If the message is smaller than udp_preference_limit, then UDP will be tried before TCP.
        /// Regardless of the size, both protocols will be tried if the first attempt fails.
        /// </summary>
        [DisplayName("udp_preference_limit")]
        public int UdpPreferenceLimit { get; set; }

        /// <summary>
        /// If this flag is true, then an attempt to verify initial credentials will fail if the client machine does not have
        /// a keytab. The default value is false.
        /// </summary>
        [DisplayName("verify_ap_req_nofail")]
        public bool VerifyApReqNoFail { get; set; }

        /// <summary>
        /// Indicates whether the client should request a PAC during AS-REQ. Default is true.
        /// </summary>
        [DefaultValue(true)]
        [DisplayName("request_pac")]
        public bool RequestPac { get; set; }
    }
}
