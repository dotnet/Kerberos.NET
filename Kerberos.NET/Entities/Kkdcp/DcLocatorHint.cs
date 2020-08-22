// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    [Flags]
#pragma warning disable CA1714 // Flags enums should have plural names
    public enum DcLocatorHint : uint
    {
        /// <summary>
        /// Forces cached domain controller data to be ignored.
        /// </summary>
        DS_FORCE_REDISCOVERY = 1 << 0,

        /// <summary>
        /// Requires that the returned domain controller support directory services.
        /// </summary>
        DS_DIRECTORY_SERVICE_REQUIRED = 1 << 1,

        /// <summary>
        /// Attempts to find a domain controller that supports directory service functions.
        /// </summary>
        DS_DIRECTORY_SERVICE_PREFERRED = 1 << 2,

        /// <summary>
        /// Requires that the returned domain controller be a global catalog server for
        /// the forest of domains with this domain as the root.
        /// </summary>
        DS_GC_SERVER_REQUIRED = 1 << 3,

        /// <summary>
        /// Requires that the returned domain controller be the primary domain controller for the domain.
        /// </summary>
        DS_PDC_REQUIRED = 1 << 4,

        /// <summary>
        /// Requests that cached domain controller data should be used.
        /// </summary>
        DS_BACKGROUND_ONLY = 1 << 5,

        /// <summary>
        /// This parameter indicates that the domain controller must have an IP address.
        /// </summary>
        DS_IP_REQUIRED = 1 << 6,

        /// <summary>
        /// Requires that the returned domain controller be currently running the Kerberos Key Distribution Center service.
        /// </summary>
        DS_KDC_REQUIRED = 1 << 7,

        /// <summary>
        /// Requires that the returned domain controller be currently running the Windows Time Service.
        /// </summary>
        DS_TIMESERV_REQUIRED = 1 << 8,

        /// <summary>
        /// Requires that the returned domain controller be writable; that is, host a writable copy of the directory service.
        /// </summary>
        DS_WRITABLE_REQUIRED = 1 << 9,

        /// <summary>
        /// Attempts to find a domain controller that is a reliable time server.
        /// </summary>
        DS_GOOD_TIMESERV_PREFERRED = 1 << 10,

        /// <summary>
        /// Specifies that the returned domain controller name should not be the current computer.
        /// </summary>
        DS_AVOID_SELF = 1 << 11,

        /// <summary>
        /// Specifies that the server returned is an LDAP server.
        /// </summary>
        DS_ONLY_LDAP_NEEDED = 1 << 12,

        /// <summary>
        /// Specifies that the DomainName parameter is a flat name. This flag cannot be combined with the DS_IS_DNS_NAME flag.
        /// </summary>
        DS_IS_FLAT_NAME = 1 << 13,

        /// <summary>
        /// Specifies that the DomainName parameter is a DNS name. This flag cannot be combined with the DS_IS_FLAT_NAME flag.
        /// </summary>
        DS_IS_DNS_NAME = 1 << 14,

        /// <summary>
        /// Attempts to find a domain controller in the same site as the caller otherwise attempts to resolve the next closest site.
        /// </summary>
        DS_TRY_NEXTCLOSEST_SITE = 1 << 15,

        /// <summary>
        /// Requires that the returned domain controller be running Windows Server 2008 or later.
        /// </summary>
        DS_DIRECTORY_SERVICE_6_REQUIRED = 1 << 16,

        /// <summary>
        /// Requires that the returned domain controller be currently running the Active Directory web service.
        /// </summary>
        DS_WEB_SERVICE_REQUIRED = 1 << 17,

        /// <summary>
        /// Requires that the returned domain controller be running Windows Server 2012 or later.
        /// </summary>
        DS_DIRECTORY_SERVICE_8_REQUIRED = 1 << 18,

        /// <summary>
        /// Requires that the returned domain controller be running Windows Server 2012 R2 or later.
        /// </summary>
        DS_DIRECTORY_SERVICE_9_REQUIRED = 1 << 19,

        /// <summary>
        /// Requires that the returned domain controller be running Windows Server 2016 or later.
        /// </summary>
        DS_DIRECTORY_SERVICE_10_REQUIRED = 1 << 20,

        //////////////////////////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// Specifies that the names returned should be DNS names.
        /// </summary>
        DS_RETURN_DNS_NAME = 1 << 30,

        /// <summary>
        /// Specifies that the names returned should be flat names.
        /// </summary>
        DS_RETURN_FLAT_NAME = unchecked(1U << 31)
    }
}