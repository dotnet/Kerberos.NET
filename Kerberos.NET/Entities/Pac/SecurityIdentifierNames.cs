using System.Collections.Generic;

namespace Kerberos.NET.Entities.Pac
{
    public static class SecurityIdentifierNames
    {
        private const string DomainPrefix = "S-1-5-21-<domain>";
        private const string MachinePrefix = "S-1-5-21-<machine>";

        public static string GetFriendlyName(string sid, string domainSid, string machineSid = null)
        {
            var template = sid.Replace(domainSid, DomainPrefix);

            if (!string.IsNullOrWhiteSpace(machineSid))
            {
                template = template.Replace(machineSid, MachinePrefix);
            }

            if (WellKnownSids.TryGetValue(template, out string name))
            {
                return name;
            }

            return sid;
        }

        private static readonly Dictionary<string, string> WellKnownSids = new Dictionary<string, string>
        {
            { "S-1-1-0",                "Everyone" },
            { "S-1-2-0",                "Local" },
            { "S-1-2-1",                "Console Logon" },
            { "S-1-3-0",                "Creator Owner" },
            { "S-1-3-1",                "Creator Group" },
            { "S-1-3-2",                "Owner Server" },
            { "S-1-3-3",                "Group Server" },
            { "S-1-3-4",                "Owner Rights" },
            { "S-1-5",                  "NT Authority" },
            { "S-1-5-1",                "Dialup" },
            { "S-1-5-2",                "Network" },
            { "S-1-5-3",                "Batch" },
            { "S-1-5-4",                "Interactive" },
            { "S-1-5-5-x-y",            "Logon Id" },
            { "S-1-5-6",                "Service" },
            { "S-1-5-7",                "Anonymous" },
            { "S-1-5-8",                "Proxy" },
            { "S-1-5-9",                "Enterprise Domain Controllers" },
            { "S-1-5-10",               "Principal Self" },
            { "S-1-5-11",               "Authenticated Users" },
            { "S-1-5-12",               "Restricted Code" },
            { "S-1-5-13",               "Terminal Server User" },
            { "S-1-5-14",               "Remote Interactive Logon" },
            { "S-1-5-15",               "This Organization" },
            { "S-1-5-17",               "IUSER" },
            { "S-1-5-18",               "Local System" },
            { "S-1-5-19",               "Local Service" },
            { "S-1-5-20",               "Network Service" },
            { "S-1-5-21-<domain>-498",  "Enterprise Readonly Domain Controllers" },
            { "S-1-5-21-0-0-0-496",     "Compounded Authentication" },
            { "S-1-5-21-0-0-0-497",     "Claims Valid" },
            { "S-1-5-21-<machine>-500", "Administrator" },
            { "S-1-5-21-<machine>-501", "Guest" },
            { "S-1-5-21-<domain>-512",  "Domain Admins" },
            { "S-1-5-21-<domain>-513",  "Domain Users" },
            { "S-1-5-21-<domain>-514",  "Domain Guests" },
            { "S-1-5-21-<domain>-515",  "Domain Computers" },
            { "S-1-5-21-<domain>-516",  "Domain Domain Controllers" },
            { "S-1-5-21-<domain>-517",  "Cert Publishers" },
            { "S-1-5-21-<domain>-518",  "Schema Administrators" },
            { "S-1-5-21-<domain>-519",  "Enterprise Admins" },
            { "S-1-5-21-<domain>-520",  "Group Policy Creator Owners" },
            { "S-1-5-21-<domain>-521",  "Readonly Domain Controllers" },
            { "S-1-5-21-<domain>-522",  "Cloneable Controllers" },
            { "S-1-5-21-<domain>-525",  "Protected Users" },
            { "S-1-5-21-<domain>-553",  "RAS Servers" },
            { "S-1-5-32-544",           "Builtin Administrators" },
            { "S-1-5-32-545",           "Builtin Users" },
            { "S-1-5-32-546",           "Builtin Guests" },
            { "S-1-5-32-547",           "Power Users" },
            { "S-1-5-32-548",           "Account Operators" },
            { "S-1-5-32-549",           "Server Operators" },
            { "S-1-5-32-550",           "Printer Operators" },
            { "S-1-5-32-551",           "Backup Operators" },
            { "S-1-5-32-552",           "Replicator" },
            { "S-1-5-32-554",           "Pre-Windows 2000 Compatible Access" },
            { "S-1-5-32-555",           "Remote Desktop" },
            { "S-1-5-32-556",           "Network Configuration Ops" },
            { "S-1-5-32-557",           "Incoming Forest Trust Builders" },
            { "S-1-5-32-558",           "Perfmon Users" },
            { "S-1-5-32-559",           "Perflog Users" },
            { "S-1-5-32-560",           "Windows Authorization Access Group" },
            { "S-1-5-32-561",           "Terminal Server License Servers" },
            { "S-1-5-32-562",           "Distributed Com Users" },
            { "S-1-5-32-568",           "IIS IUSRS" },
            { "S-1-5-32-569",           "Cryptographic Operators" },
            { "S-1-5-32-573",           "Event Log Readers" },
            { "S-1-5-32-574",           "Certificate Service Dcom Access" },
            { "S-1-5-32-575",           "RDS Remote Access Servers" },
            { "S-1-5-32-576",           "RDS Endpoint Servers" },
            { "S-1-5-32-577",           "RDS Management Servers" },
            { "S-1-5-32-578",           "Hyper-V Admins" },
            { "S-1-5-32-579",           "Access Control Assistance Ops" },
            { "S-1-5-32-580",           "Remote Management Users" },
            { "S-1-5-33",               "Write Restricted Code" },
            { "S-1-5-64-10",            "NTLM Authentication" },
            { "S-1-5-64-14",            "Schannel Authentication" },
            { "S-1-5-64-21",            "Digest Authentication" },
            { "S-1-5-65-1",             "This Organization Certificate" },
            { "S-1-5-80",               "NT Service" },
            { "S-1-5-84-0-0-0-0-0",     "User Mode Drivers" },
            { "S-1-5-113",              "Local Account" },
            { "S-1-5-114",              "Local Account and Member of Administrators Group" },
            { "S-1-5-1000",             "Other Organization" },
            { "S-1-15-2-1",             "All App Packages" },
            { "S-1-16-0",               "ML Untrusted" },
            { "S-1-16-4096",            "ML Low" },
            { "S-1-16-8192",            "ML Medium" },
            { "S-1-16-8448",            "ML Medium Plus" },
            { "S-1-16-12288",           "ML High" },
            { "S-1-16-16384",           "ML System" },
            { "S-1-16-20480",           "ML Protected Process" },
            { "S-1-18-1",               "Authentication Authority Asserted Identity" },
            { "S-1-18-2",               "Service Asserted Identity" },
            { "S-1-18-3",               "Fresh Public Key Identity" },
            { "S-1-18-4",               "Key Trust Identity" },
            { "S-1-18-5",               "Key Property MFA" },
            { "S-1-18-6",               "Key Property Attestation" }
        };
    }
}