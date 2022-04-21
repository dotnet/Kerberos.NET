// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;
using Kerberos.NET.Server;

namespace Kerberos.NET.Configuration
{
    public class Krb5RealmConfig : Krb5ConfigObject
    {
        /// <summary>
        /// Identifies the host where the administration server is running. Typically, this is the primary Kerberos server.
        /// This tag must be given a value in order to communicate with the the admin service server for the realm.
        /// </summary>
        [DisplayName("admin_server")]
        public ICollection<string> AdminServer { get; private set; }

        /// <summary>
        /// This tag allows you to set a general rule for mapping principal names to local user names.
        /// It will be used if there is not an explicit mapping for the principal name that is being translated.
        /// </summary>
        [DisplayName("auth_to_local")]
        public ICollection<string> AuthToLocal { get; private set; }

        /// <summary>
        /// This subsection allows you to set explicit mappings from principal names to local user names.
        /// The tag is the mapping name, and the value is the corresponding local user name.
        /// </summary>
        [DisplayName("auth_to_local_names")]
        public IDictionary<string, string> AuthToLocalNames { get; private set; }

        /// <summary>
        /// This tag specifies the domain used to expand hostnames when translating Kerberos 4 service principals
        /// to Kerberos 5 principals (for example, when converting rcmd.hostname to host/hostname.domain).
        /// </summary>
        [DisplayName("default_domain")]
        public string DefaultDomain { get; set; }

        /// <summary>
        /// If this flag is true, the client will not perform encrypted timestamp preauthentication if requested by the KDC
        /// Setting this flag can help to prevent dictionary attacks by active attackers, if the realm’s KDCs support SPAKE
        /// preauthentication or if initial authentication always uses another mechanism or always uses FAST. This flag
        /// persists across client referrals during initial authentication. This flag does not prevent the KDC from offering
        /// encrypted timestamp.
        /// </summary>
        [DisplayName("disable_encrypted_timestamp")]
        public bool DisableEncryptedTimestamps { get; set; }

        /// <summary>
        /// When KDCs and kpasswd servers are accessed through HTTPS proxies, this tag can be used to specify the location
        /// of the CA certificate which should be trusted to issue the certificate for a proxy server. If left unspecified,
        /// the system-wide default set of CA certificates is used.
        /// </summary>
        [DisplayName("http_anchors")]
        public string HttpAnchors { get; set; }

        /// <summary>
        /// The name or address of a host running a KDC for that realm. An optional port number, separated from the hostname
        /// by a colon, may be included. For your computer to be able to communicate with the KDC for each realm, this tag
        /// must be given a value in each realm subsection in the configuration file, or there must be DNS SRV records
        /// specifying the KDCs.
        /// </summary>
        [DisplayName("kdc")]
        public ICollection<string> Kdc { get; private set; }

        /// <summary>
        /// Points to the server where all the password changes are performed. If there is no such entry, DNS will be
        /// queried (unless forbidden by dns_lookup_kdc). Finally, port 464 on the admin_server host will be tried.
        /// </summary>
        [DisplayName("kpasswd_server")]
        public ICollection<string> KPasswdServer { get; private set; }

        /// <summary>
        /// Specifies the location of trusted anchor (root) certificates which the client trusts to sign KDC certificates.
        /// This option may be specified multiple times.
        /// </summary>
        [DisplayName("pkinit_anchors")]
        public ICollection<string> PkInitAnchors { get; private set; }

        /// <summary>
        /// Specifies matching rules that the client certificate must match before it is used to attempt PKINIT authentication.
        /// If a user has multiple certificates available (on a smart card, or via other media), there must be exactly one certificate
        /// chosen before attempting PKINIT authentication. This option may be specified multiple times. All the available certificates
        /// are checked against each rule in order until there is a match of exactly one certificate.
        /// </summary>
        [DisplayName("pkinit_cert_match")]
        public ICollection<string> PkInitCertificateMatch { get; private set; }

        /// <summary>
        /// This option specifies what Extended Key Usage value the KDC certificate presented to the client must contain.
        /// </summary>
        [DisplayName("pkinit_eku_checking")]
        public PkInitEkuCheck PkInitEkuChecking { get; set; }

        /// <summary>
        /// Specifies the size of the Diffie-Hellman key the client will attempt to use. The acceptable values are 2048 and 4096.
        /// The default is 2048.
        /// </summary>
        [DefaultValue(2048)]
        [DisplayName("pkinit_dh_min_bits")]
        public int PkInitDhMinimumBits { get; set; }

        /// <summary>
        /// Specifies the location(s) to be used to find the user’s X.509 identity information. If this option is specified multiple times,
        /// the first valid value is used; this can be used to specify an environment variable (with ENV:envvar) followed by a default value.
        /// </summary>
        [DisplayName("pkinit_identities")]
        public ICollection<string> PkInitIdentities { get; private set; }

        /// <summary>
        /// The presence of this option indicates that the client is willing to accept a KDC certificate with a dNSName SAN (Subject Alternative Name)
        /// rather than requiring the id-pkinit-san as defined in RFC 4556. This option may be specified multiple times. Its value should contain the
        /// acceptable hostname for the KDC (as contained in its certificate).
        /// </summary>
        [DisplayName("pkinit_kdc_hostname")]
        public ICollection<string> PkInitKdcHostname { get; private set; }

        /// <summary>
        /// Specifies the location of intermediate certificates which may be used by the client to complete the trust chain between a KDC certificate
        /// and a trusted anchor. This option may be specified multiple times.
        /// </summary>
        [DisplayName("pkinit_pool")]
        public ICollection<string> PkInitPool { get; private set; }

        /// <summary>
        /// If a match is found for the certificate in a CRL, verification fails. If the certificate being verified is not listed in a CRL,
        /// or there is no CRL present for its issuing CA, and pkinit_require_crl_checking is false, then verification succeeds.
        /// </summary>
        [DisplayName("pkinit_require_crl_checking")]
        public bool PkInitRequireCrlChecking { get; set; }

        /// <summary>
        /// Specifies the location of Certificate Revocation List (CRL) information to be used by the client when verifying the
        /// validity of the KDC certificate presented.
        /// </summary>
        [DisplayName("pkinit_revoke")]
        public ICollection<string> PkInitRevoke { get; private set; }

        /// <summary>
        /// Identifies the primary KDC(s). Currently, this tag is used in only one case: If an attempt to get credentials
        /// fails because of an invalid password, the client software will attempt to contact the primary KDC, in case the
        /// user’s password has just been changed, and the updated database has not been propagated to the replica servers yet.
        /// </summary>
        [DisplayName("master_kdc")]
        public ICollection<string> PrimaryKdc { get; private set; }

        /// <summary>
        /// This subsection allows the administrator to configure exceptions to the default_domain mapping rule. It contains V4
        /// instances (the tag name) which should be translated to some specific hostname (the tag value) as the second component
        /// in a Kerberos V5 principal name.
        /// </summary>
        [DisplayName("v4_instance_convert")]
        public IDictionary<string, string> V4InstanceConvert { get; private set; }

        [DisplayName("v4_name_convert")]
        public IDictionary<string, IDictionary<string, string>> V4NameConvert { get; private set; }

        /// <summary>
        /// This relation is used when converting a V5 principal name to a V4 principal name. It is used when the V4 realm name and the
        /// V5 realm name are not the same, but still share the same principal names and passwords. The tag value is the Kerberos V4 realm name.
        /// </summary>
        [DisplayName("v4_realm")]
        public IDictionary<string, string> V4Realm { get; private set; }

        ////////////////////// KDC Configuration /////////////////////////

        /// <summary>
        /// KDC Server setting: Location of the access control list file that the admin service uses to determine which principals are allowed which permissions on the Kerberos database.
        /// </summary>
        [DisplayName("acl_file")]
        public string KdcAclFile { get; set; }

        /// <summary>
        /// KDC Server setting: This relation indicates the name of the configuration section under [dbmodules] for database-specific parameters used by the loadable database library.
        /// The default value is the realm name. If this configuration section does not exist, default values will be used for all database parameters.
        /// </summary>
        [DisplayName("database_module")]
        public string KdcDatabaseModule { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies the default expiration date of principals created in this realm. The default value is 0, which means no expiration date.
        /// </summary>
        [DefaultValue("0")]
        [DisplayName("default_principal_expiration")]
        public DateTimeOffset KdcDefaultPrincipalExpiration { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies the default attributes of principals created in this realm. The format for this string is a comma-separated list of flags,
        /// with ‘+’ before each flag that should be enabled and ‘-‘ before each flag that should be disabled.
        /// The postdateable, forwardable, tgt-based, renewable, proxiable, dup-skey, allow-tickets, and service flags default to enabled.
        /// </summary>
        [DefaultValue("+postdateable, +forwardable, +tgt-based, +renewable, +proxiable, +dup-skey, +allow-tickets, +service")]
        [DisplayName("default_principal_flags")]
        public FlagString<PrincipalFlags> KdcDefaultPrincipalFlags { get; set; }

        /// <summary>
        /// KDC Server setting: Location of the dictionary file containing strings that are not allowed as passwords. The file should contain one string per line,
        /// with no additional whitespace. If none is specified or if there is no policy assigned to the principal, no dictionary
        /// checks of passwords will be performed.
        /// </summary>
        [DisplayName("dict_file")]
        public string KdcDictionaryFilePath { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies the authentication indicator value that the KDC asserts into tickets obtained using FAST encrypted challenge pre-authentication.
        /// </summary>
        [DisplayName("encrypted_challenge_indicator")]
        public string KdcEncryptedChallenegeIndicator { get; set; }

        /// <summary>
        /// KDC Server setting: Lists services which will get host-based referral processing even if the server principal is not marked as host-based by the client.
        /// </summary>
        [DisplayName("host_based_services")]
        public ICollection<string> KdcHostBasedServices { get; private set; }

        /// <summary>
        /// KDC Server setting: Specifies whether incremental database propagation is enabled. The default value is false.
        /// </summary>
        [DisplayName("iprop_enabled")]
        public bool KdcIncrementalPropagationEnabled { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies the maximum number of log entries to be retained for incremental propagation.
        /// </summary>
        [DefaultValue(1000)]
        [DisplayName("iprop_ulogsize")]
        public int KdcIncrementalPropagationLogSize { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies how often the replica KDC polls for new updates from the primary.
        /// </summary>
        [DefaultValue("2m")]
        [DisplayName("iprop_replica_poll")]
        public TimeSpan KdcIncrementalPropagationReplicaPoll { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies the iprop RPC listening addresses and/or ports for the the admin service. Each entry may be an interface address,
        /// a port number, or an address and port number separated by a colon. If the address contains colons, enclose it in square brackets.
        /// If no address is specified, the wildcard address is used.
        /// </summary>
        [DefaultValue("127.0.0.1:754")]
        [DisplayName("iprop_listen")]
        public ICollection<string> KdcIncrementalPropagationListenEndpoints { get; private set; }

        /// <summary>
        /// KDC Server setting: Specifies the amount of time to wait for a full propagation to complete. This is optional in configuration files, and is used by replica KDCs only.
        /// </summary>
        [DefaultValue("5m")]
        [DisplayName("iprop_resync_timeout")]
        public TimeSpan KdcIncrementalPropagationResyncTimeout { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies the admin service RPC listening addresses and/or ports for the the admin service. Each entry may be an interface address, a port number, or an address
        /// and port number separated by a colon. If the address contains colons, enclose it in square brackets. If no address is specified, the wildcard address
        /// is used.
        /// </summary>
        [DefaultValue("127.0.0.1:749")]
        [DisplayName("kadmind_listen")]
        public ICollection<string> KdcAdminServiceListenEndpoints { get; private set; }

        /// <summary>
        /// KDC Server setting: Specifies the location where the system key has been stored.
        /// </summary>
        [DisplayName("key_stash_file")]
        public string KdcKeyStashFile { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies the UDP listening addresses and/or ports for the KDC service. Each entry may be an interface address, a port number, or an address and port number separated by a colon.
        /// If the address contains colons, enclose it in square brackets. If no address is specified, the wildcard address is used. If no port is specified, the standard port (88) is used.
        /// </summary>
        [DefaultValue("127.0.0.1:88")]
        [DisplayName("kdc_listen")]
        public ICollection<string> KdcListenEndpoints { get; private set; }

        /// <summary>
        /// KDC Server setting: Specifies the TCP listening addresses and/or ports for the KDC service. Each entry may be an interface address, a port number, or an address and port number separated by a colon.
        /// If the address contains colons, enclose it in square brackets. If no address is specified, the wildcard address is used. If no port is specified, the standard port (88) is used.
        /// To disable listening on TCP, set this relation to the empty string with kdc_tcp_listen = "".
        /// </summary>
        [DefaultValue("127.0.0.1:88")]
        [DisplayName("kdc_tcp_listen")]
        public ICollection<string> KdcTcpListenEndpoints { get; private set; }

        /// <summary>
        /// KDC Server setting: Specifies the kpasswd listening addresses and/or ports for the the admin service. Each entry may be an interface address, a port number, or an address and port number separated by a colon.
        /// If the address contains colons, enclose it in square brackets. If no address is specified, the wildcard address is used. If the admin service fails to bind to any of the specified addresses,
        /// it will fail to start.
        /// </summary>
        [DefaultValue("127.0.0.1:464")]
        [DisplayName("kpasswd_listen")]
        public ICollection<string> KdcPasswordListenEndpoints { get; private set; }

        /// <summary>
        /// KDC Server setting: Specifies the maximum time period for which a ticket may be valid in this realm. The default value is 24 hours.
        /// </summary>
        [DefaultValue("24h")]
        [DisplayName("max_life")]
        public TimeSpan KdcMaxTicketLifetime { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies the maximum time period during which a valid ticket may be renewed in this realm. The default value is 0.
        /// </summary>
        [DisplayName("max_renewable_life")]
        public TimeSpan KdcMaxRenewableLifetime { get; set; }

        /// <summary>
        /// KDC Server setting: Lists services to block from getting host-based referral processing, even if the client marks the server principal as host-based or
        /// the service is also listed in host_based_services. no_host_referral = * will disable referral processing altogether.
        /// </summary>
        [DisplayName("no_host_referral")]
        public ICollection<string> KdcNoHostReferral { get; private set; }

        /// <summary>
        /// KDC Server setting: If set to true, the KDC will check the list of transited realms for cross-realm tickets against the transit path computed from the realm names and the capaths section of its krb5.conf file;
        /// if the path in the ticket to be issued contains any realms not in the computed path, the ticket will not be issued, and an error will be returned to the client instead.
        /// If this value is set to false, such tickets will be issued anyways, and it will be left up to the application server to validate the realm transit path.
        /// If the disable-transited-check flag is set in the incoming request, this check is not performed at all.Having the reject_bad_transit option will cause such ticket requests to be rejected always.
        /// This transit path checking and config file option currently apply only to TGS requests.
        /// </summary>
        [DefaultValue(true)]
        [DisplayName("reject_bad_transit")]
        public bool KdcRejectBadTransit { get; set; }

        /// <summary>
        /// KDC Server setting: If set to true, the KDC will reject ticket requests from anonymous principals to service principals other than the realm’s ticket-granting service.
        /// This option allows anonymous PKINIT to be enabled for use as FAST armor tickets without allowing anonymous authentication to services.
        /// </summary>
        [DisplayName("restrict_anonymous_to_tgt")]
        public bool KdcRestrictAnonymousToTicketGrantingService { get; set; }

        /// <summary>
        /// KDC Server setting: Specifies an authentication indicator value that the KDC asserts into tickets obtained using SPAKE pre-authentication.
        /// The default is not to add any indicators. This option may be specified multiple times.
        /// </summary>
        [DisplayName("spake_preauth_indicator")]
        public ICollection<string> KdcSpakePreAuthIndicator { get; private set; }

        /// <summary>
        /// KDC Server setting: Specifies the default key/salt combinations of principals for this realm.
        /// </summary>
        [DefaultValue("aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal")]
        [DisplayName("supported_enctypes")]
        public ICollection<KeySaltPair> KdcSupportedEncryptionTypes { get; private set; }

        /// <summary>
        /// Compatibility shims should be enforced by the KDC.
        /// </summary>
        [EnumAsInteger]
        [DefaultValue(KerberosCompatibilityFlags.None)]
        [DisplayName("compatibility_flags")]
        public KerberosCompatibilityFlags CompatibilityFlags { get; set; }
    }
}
