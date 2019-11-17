using System;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum DcLocatorHint : uint
    {
        DS_FORCE_REDISCOVERY = 1 << 0,
        DS_DIRECTORY_SERVICE_REQUIRED = 1 << 1,
        DS_DIRECTORY_SERVICE_PREFERRED = 1 << 2,
        DS_GC_SERVER_REQUIRED = 1 << 3,
        DS_PDC_REQUIRED = 1 << 4,
        DS_BACKGROUND_ONLY = 1 << 5,
        DS_IP_REQUIRED = 1 << 6,
        DS_KDC_REQUIRED = 1 << 7,
        DS_TIMESERV_REQUIRED = 1 << 8,
        DS_WRITABLE_REQUIRED = 1 << 9,
        DS_GOOD_TIMESERV_PREFERRED = 1 << 10,
        DS_AVOID_SELF = 1 << 11,
        DS_ONLY_LDAP_NEEDED = 1 << 12,
        DS_IS_FLAT_NAME = 1 << 13,
        DS_IS_DNS_NAME = 1 << 14,
        DS_TRY_NEXTCLOSEST_SITE = 1 << 15,
        DS_DIRECTORY_SERVICE_6_REQUIRED = 1 << 16,
        DS_WEB_SERVICE_REQUIRED = 1 << 17,
        DS_DIRECTORY_SERVICE_8_REQUIRED = 1 << 18,
        DS_DIRECTORY_SERVICE_9_REQUIRED = 1 << 19,
        DS_DIRECTORY_SERVICE_10_REQUIRED = 1 << 20,

        DS_RETURN_DNS_NAME = 1 << 30,
        DS_RETURN_FLAT_NAME = unchecked((uint)1 << 31)
    }
}
