// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.ComponentModel;

namespace Kerberos.NET.Configuration
{
    public class Krb5KdcDefaults : Krb5ConfigObject
    {
        /// <summary>
        /// Specifies the maximum packet size that can be sent over UDP. The default value is 4096 bytes.
        /// </summary>
        [DefaultValue(4096)]
        [DisplayName("kdc_max_dgram_reply_size")]
        public int MaxDatagramReplySize { get; set; }

        /// <summary>
        /// Set the size of the listen queue length for the KDC daemon. The value may be limited by OS settings. The default value is 5.
        /// </summary>
        [DefaultValue(5)]
        [DisplayName("kdc_tcp_listen_backlog")]
        public int TcpListenBacklog { get; set; }

        /// <summary>
        /// Specifies the group for a SPAKE optimistic challenge.
        /// </summary>
        [DisplayName("spake_preauth_kdc_challenge")]
        public string SpakePreAuthKdcChallenge { get; set; }

        /// <summary>
        /// Lists services which will get host-based referral processing even if the server principal is not marked as host-based by the client.
        /// </summary>
        [DisplayName("host_based_services")]
        public ICollection<string> HostBasedServices { get; private set; }

        /// <summary>
        /// Specifies the UDP listening addresses and/or ports for the krb5kdc daemon. Each entry may be an interface address, a port number, or an address and port number separated by a colon.
        /// If the address contains colons, enclose it in square brackets. If no address is specified, the wildcard address is used. If no port is specified, the standard port (88) is used.
        /// If the KDC daemon fails to bind to any of the specified addresses, it will fail to start. The default is to bind to the wildcard address on the standard port.
        /// </summary>
        [DefaultValue("127.0.0.1:88")]
        [DisplayName("kdc_listen")]
        public ICollection<string> KdcListenEndpoints { get; private set; }

        /// <summary>
        /// Specifies the TCP listening addresses and/or ports for the krb5kdc daemon. Each entry may be an interface address, a port number, or an address and port number separated by a colon.
        /// If the address contains colons, enclose it in square brackets. If no address is specified, the wildcard address is used. If no port is specified, the standard port (88) is used.
        /// To disable listening on TCP, set this relation to the empty string with kdc_tcp_listen = "". If the KDC daemon fails to bind to any of the specified addresses, it will fail to start.
        /// The default is to bind to the wildcard address on the standard port.
        /// </summary>
        [DefaultValue("127.0.0.1:88")]
        [DisplayName("kdc_tcp_listen")]
        public ICollection<string> KdcTcpListenEndpoints { get; private set; }

        /// <summary>
        /// Lists services to block from getting host-based referral processing, even if the client marks the server principal as host-based or
        /// the service is also listed in host_based_services. no_host_referral = * will disable referral processing altogether.
        /// </summary>
        [DisplayName("no_host_referral")]
        public ICollection<string> NoHostReferral { get; private set; }

        /// <summary>
        /// If set to true, the KDC will reject ticket requests from anonymous principals to service principals other than the realm’s ticket-granting service.
        /// This option allows anonymous PKINIT to be enabled for use as FAST armor tickets without allowing anonymous authentication to services.
        /// </summary>
        [DisplayName("restrict_anonymous_to_tgt")]
        public bool RestrictAnonymousToTicketGrantingTicketService { get; set; }
    }
}
