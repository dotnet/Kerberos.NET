// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.ComponentModel;

namespace Kerberos.NET.Configuration
{
    public class Krb5RealmConfig
    {
        /// <summary>
        /// Identifies the host where the administration server is running. Typically, this is the primary Kerberos server.
        /// This tag must be given a value in order to communicate with the kadmind server for the realm.
        /// </summary>
        [DisplayName("admin_server")]
        public IEnumerable<string> AdminServer { get; set; }

        /// <summary>
        /// This tag allows you to set a general rule for mapping principal names to local user names.
        /// It will be used if there is not an explicit mapping for the principal name that is being translated.
        /// </summary>
        [DisplayName("auth_to_local")]
        public IEnumerable<string> AuthToLocal { get; set; }

        /// <summary>
        /// This subsection allows you to set explicit mappings from principal names to local user names.
        /// The tag is the mapping name, and the value is the corresponding local user name.
        /// </summary>
        [DisplayName("auth_to_local_names")]
        public IDictionary<string, string> AuthToLocalNames { get; set; }

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
        public string HttpAnchors { get; set; }

        /// <summary>
        /// The name or address of a host running a KDC for that realm. An optional port number, separated from the hostname
        /// by a colon, may be included. For your computer to be able to communicate with the KDC for each realm, this tag
        /// must be given a value in each realm subsection in the configuration file, or there must be DNS SRV records
        /// specifying the KDCs.
        /// </summary>
        [DisplayName("kdc")]
        public IEnumerable<string> Kdc { get; set; }

        /// <summary>
        /// Points to the server where all the password changes are performed. If there is no such entry, DNS will be
        /// queried (unless forbidden by dns_lookup_kdc). Finally, port 464 on the admin_server host will be tried.
        /// </summary>
        [DisplayName("kpasswd_server")]
        public IEnumerable<string> KPasswdServer { get; set; }

        /// <summary>
        /// Specifies the location of trusted anchor (root) certificates which the client trusts to sign KDC certificates.
        /// This option may be specified multiple times.
        /// </summary>
        [DisplayName("pkinit_anchors")]
        public IEnumerable<string> PkInitAnchors { get; set; }

        /// <summary>
        /// Specifies matching rules that the client certificate must match before it is used to attempt PKINIT authentication.
        /// If a user has multiple certificates available (on a smart card, or via other media), there must be exactly one certificate
        /// chosen before attempting PKINIT authentication. This option may be specified multiple times. All the available certificates
        /// are checked against each rule in order until there is a match of exactly one certificate.
        /// </summary>
        [DisplayName("pkinit_cert_match")]
        public IEnumerable<string> PkInitCertificateMatch { get; set; }

        /// <summary>
        /// This option specifies what Extended Key Usage value the KDC certificate presented to the client must contain.
        /// </summary>
        [DisplayName("pkinit_eku_checking")]
        public PkInitEkuCheck PkInitEkuChecking { get; set; }

        /// <summary>
        /// Specifies the size of the Diffie-Hellman key the client will attempt to use. The acceptable values are 1024, 2048, and 4096.
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
        public IEnumerable<string> PkInitIdentities { get; set; }

        /// <summary>
        /// The presence of this option indicates that the client is willing to accept a KDC certificate with a dNSName SAN (Subject Alternative Name)
        /// rather than requiring the id-pkinit-san as defined in RFC 4556. This option may be specified multiple times. Its value should contain the
        /// acceptable hostname for the KDC (as contained in its certificate).
        /// </summary>
        [DisplayName("pkinit_kdc_hostname")]
        public IEnumerable<string> PkInitKdcHostname { get; set; }

        /// <summary>
        /// Specifies the location of intermediate certificates which may be used by the client to complete the trust chain between a KDC certificate
        /// and a trusted anchor. This option may be specified multiple times.
        /// </summary>
        [DisplayName("pkinit_pool")]
        public IEnumerable<string> PkInitPool { get; set; }

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
        public IEnumerable<string> PkInitRevoke { get; set; }

        /// <summary>
        /// Identifies the primary KDC(s). Currently, this tag is used in only one case: If an attempt to get credentials
        /// fails because of an invalid password, the client software will attempt to contact the master KDC, in case the
        /// user’s password has just been changed, and the updated database has not been propagated to the replica servers yet.
        /// </summary>
        [DisplayName("master_kdc")]
        public IEnumerable<string> PrimaryKdc { get; set; }

        /// <summary>
        /// This subsection allows the administrator to configure exceptions to the default_domain mapping rule. It contains V4
        /// instances (the tag name) which should be translated to some specific hostname (the tag value) as the second component
        /// in a Kerberos V5 principal name.
        /// </summary>
        [DisplayName("v4_instance_convert")]
        public IDictionary<string, string> V4InstanceConvert { get; set; }

        [DisplayName("v4_name_convert")]
        public IDictionary<string, IDictionary<string, string>> V4NameConvert { get; set; }

        /// <summary>
        /// This relation is used when converting a V5 principal name to a V4 principal name. It is used when the V4 realm name and the
        /// V5 realm name are not the same, but still share the same principal names and passwords. The tag value is the Kerberos V4 realm name.
        /// </summary>
        [DisplayName("v4_realm")]
        public IDictionary<string, string> V4Realm { get; set; }
    }
}
