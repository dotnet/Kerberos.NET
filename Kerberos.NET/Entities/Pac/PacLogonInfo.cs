using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities.Pac
{
    [Flags]
    public enum UserFlags
    {
        LOGON_GUEST = 1,
        LOGON_NOENCRYPTION = 2,
        LOGON_CACHED_ACCOUNT = 4,
        LOGON_USED_LM_PASSWORD = 8,
        LOGON_EXTRA_SIDS = 32,
        LOGON_SUBAUTH_SESSION_KEY = 64,
        LOGON_SERVER_TRUST_ACCOUNT = 128,
        LOGON_NTLMV2_ENABLED = 256,
        LOGON_RESOURCE_GROUPS = 512,
        LOGON_PROFILE_PATH_RETURNED = 1024,
        LOGON_GRACE_LOGON = 16777216,
        LOGON_NT_V2 = 0x800,
        LOGON_LM_V2 = 0x1000,
        LOGON_NTLM_V2 = 0x2000,
        LOGON_OPTIMIZED = 0x4000,
        LOGON_WINLOGON = 0x8000,
        LOGON_PKINIT = 0x10000,
        LOGON_NO_OPTIMIZED = 0x20000
    }

    [Flags]
    public enum UserAccountControlFlags
    {
        ADS_UF_ACCOUNT_DISABLE = 2,
        ADS_UF_HOMEDIR_REQUIRED = 8,
        ADS_UF_LOCKOUT = 16,
        ADS_UF_PASSWD_NOTREQD = 32,
        ADS_UF_PASSWD_CANT_CHANGE = 64,
        ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128,
        ADS_UF_NORMAL_ACCOUNT = 512,
        ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 2048,
        ADS_UF_WORKSTATION_TRUST_ACCOUNT = 4096,
        ADS_UF_SERVER_TRUST_ACCOUNT = 8192,
        ADS_UF_DONT_EXPIRE_PASSWD = 65536,
        ADS_UF_MNS_LOGON_ACCOUNT = 131072,
        ADS_UF_SMARTCARD_REQUIRED = 262144,
        ADS_UF_TRUSTED_FOR_DELEGATION = 524288,
        ADS_UF_NOT_DELEGATED = 1048576,
        ADS_UF_USE_DES_KEY_ONLY = 2097152,
        ADS_UF_DONT_REQUIRE_PREAUTH = 4194304,
        ADS_UF_PASSWORD_EXPIRED = 8388608,
        ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216,
        ADS_UF_NO_AUTH_DATA_REQUIRED = 33554432,
        ADS_UF_PARTIAL_SECRETS_ACCOUNT = 67108864
    }

    public class PacLogonInfo : NdrMessage
    {
        public PacLogonInfo(byte[] node)
            : base(node)
        {
            LogonTime = Stream.ReadFiletime();
            LogoffTime = Stream.ReadFiletime();
            KickOffTime = Stream.ReadFiletime();
            PwdLastChangeTime = Stream.ReadFiletime();
            PwdCanChangeTime = Stream.ReadFiletime();
            PwdMustChangeTime = Stream.ReadFiletime();

            var userName = Stream.ReadRPCUnicodeString();
            var userDisplayName = Stream.ReadRPCUnicodeString();
            var logonScript = Stream.ReadRPCUnicodeString();
            var profilePath = Stream.ReadRPCUnicodeString();
            var homeDirectory = Stream.ReadRPCUnicodeString();
            var homeDrive = Stream.ReadRPCUnicodeString();

            LogonCount = Stream.ReadShort();
            BadPasswordCount = Stream.ReadShort();

            var userSid = Stream.ReadRid();
            var groupSid = Stream.ReadRid();

            // Groups information
            var groupCount = Stream.ReadInt();
            var groupPointer = Stream.ReadInt();

            UserFlags = (UserFlags)Stream.ReadInt();

            // sessionKey
            Stream.Read(new byte[16]);

            var serverNameString = Stream.ReadRPCUnicodeString();
            var domainNameString = Stream.ReadRPCUnicodeString();
            var domainIdPointer = Stream.ReadInt();

            // reserved1
            Stream.Read(new byte[8]);

            UserAccountControl = (UserAccountControlFlags)Stream.ReadInt();

            SubAuthStatus = Stream.ReadInt();
            LastSuccessfulILogon = Stream.ReadFiletime();
            LastFailedILogon = Stream.ReadFiletime();
            FailedILogonCount = Stream.ReadInt();

            // reserved3
            Stream.ReadInt();

            // Extra SIDs information
            var extraSidCount = Stream.ReadInt();
            var extraSidPointer = Stream.ReadInt();

            var resourceDomainIdPointer = Stream.ReadInt();
            var resourceGroupCount = Stream.ReadInt();
            var resourceGroupPointer = Stream.ReadInt();

            UserName = userName.ReadString(Stream);
            UserDisplayName = userDisplayName.ReadString(Stream);
            LogonScript = logonScript.ReadString(Stream);
            ProfilePath = profilePath.ReadString(Stream);
            HomeDirectory = homeDirectory.ReadString(Stream);
            HomeDrive = homeDrive.ReadString(Stream);

            // Groups data
            var groupSids = ParseAttributes(Stream, groupCount, groupPointer);

            // Server related strings
            ServerName = serverNameString.ReadString(Stream);
            DomainName = domainNameString.ReadString(Stream);

            if (domainIdPointer != 0)
            {
                DomainSid = Stream.ReadSid();
            }

            UserSid = userSid.AppendTo(DomainSid);
            GroupSid = groupSid.AppendTo(DomainSid);

            GroupSids = groupSids.Select(g => g.AppendTo(DomainSid)).ToList();

            if (UserFlags.HasFlag(UserFlags.LOGON_EXTRA_SIDS))
            {
                ExtraSids = ParseExtraSids(Stream, extraSidCount, extraSidPointer).ToList();
            }

            if (resourceDomainIdPointer != 0)
            {
                ResourceDomainSid = Stream.ReadSid();
            }

            if (UserFlags.HasFlag(UserFlags.LOGON_RESOURCE_GROUPS))
            {
                ResourceGroups = ParseAttributes(
                    Stream,
                    resourceGroupCount,
                    resourceGroupPointer
                ).Select(g => g.AppendTo(ResourceDomainSid)).ToList();
            }
        }

        private static SecurityIdentifier[] ParseExtraSids(NdrBinaryReader Stream, int extraSidCount, int extraSidPointer)
        {
            if (extraSidPointer == 0)
            {
                return new SecurityIdentifier[0];
            }

            int realExtraSidCount = Stream.ReadInt();

            if (realExtraSidCount != extraSidCount)
            {
                throw new InvalidDataException($"Expected Sid count {extraSidCount} doesn't match actual sid count {realExtraSidCount}");
            }

            var extraSidAtts = new SecurityIdentifier[extraSidCount];

            var pointers = new int[extraSidCount];
            var attributes = new SidAttributes[extraSidCount];

            for (int i = 0; i < extraSidCount; i++)
            {
                pointers[i] = Stream.ReadInt();
                attributes[i] = (SidAttributes)Stream.ReadUnsignedInt();
            }

            for (int i = 0; i < extraSidCount; i++)
            {
                SecurityIdentifier sid = null;

                if (pointers[i] != 0)
                {
                    sid = new SecurityIdentifier(Stream.ReadSid(), attributes[i]);
                }

                extraSidAtts[i] = sid;
            }

            return extraSidAtts;
        }

        private static IEnumerable<SecurityIdentifier> ParseAttributes(NdrBinaryReader Stream, int count, int pointer)
        {
            var attributes = new List<SecurityIdentifier>();

            if (pointer == 0)
            {
                return attributes;
            }

            int realCount = Stream.ReadInt();

            if (realCount != count)
            {
                throw new InvalidDataException($"Expected count {count} doesn't match actual count {realCount}");
            }

            for (int i = 0; i < count; i++)
            {
                Stream.Align(4);

                var sid = Stream.ReadRid();

                attributes.Add(new SecurityIdentifier(sid, (SidAttributes)Stream.ReadInt()));
            }

            return attributes;
        }

        public DateTimeOffset LogonTime { get; }

        public DateTimeOffset LogoffTime { get; }

        public DateTimeOffset KickOffTime { get; }

        public DateTimeOffset PwdLastChangeTime { get; }

        public DateTimeOffset PwdCanChangeTime { get; }

        public DateTimeOffset PwdMustChangeTime { get; }

        public long LogonCount { get; }

        public long BadPasswordCount { get; }

        public string UserName { get; }

        public string UserDisplayName { get; }

        public string LogonScript { get; }

        public string ProfilePath { get; }

        public string HomeDirectory { get; }

        public string HomeDrive { get; }

        public string ServerName { get; }

        public string DomainName { get; }

        public SecurityIdentifier UserSid { get; }

        public SecurityIdentifier GroupSid { get; }

        public IEnumerable<SecurityIdentifier> GroupSids { get; }

        public IEnumerable<SecurityIdentifier> ExtraSids { get; }

        public UserAccountControlFlags UserAccountControl { get; }

        public UserFlags UserFlags { get; }

        public int FailedILogonCount { get; }

        public DateTimeOffset LastFailedILogon { get; }

        public DateTimeOffset LastSuccessfulILogon { get; }

        public int SubAuthStatus { get; }

        public SecurityIdentifier ResourceDomainSid { get; }

        public IEnumerable<SecurityIdentifier> ResourceGroups { get; }

        public SecurityIdentifier DomainSid { get; }
    }
}