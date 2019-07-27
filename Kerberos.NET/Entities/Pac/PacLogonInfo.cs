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

    public class PacLogonInfo : NdrMessage, IPacElement
    {
        public PacType PacType => PacType.LOGON_INFO;

        public override void WriteBody(NdrBinaryStream stream)
        {
            stream.WriteFiletime(LogonTime);
            stream.WriteFiletime(LogoffTime);
            stream.WriteFiletime(KickOffTime);
            stream.WriteFiletime(PwdLastChangeTime);
            stream.WriteFiletime(PwdCanChangeTime);
            stream.WriteFiletime(PwdMustChangeTime);

            stream.WriteRPCUnicodeString(UserName);
            stream.WriteRPCUnicodeString(UserDisplayName);
            stream.WriteRPCUnicodeString(LogonScript);
            stream.WriteRPCUnicodeString(ProfilePath);
            stream.WriteRPCUnicodeString(HomeDirectory);
            stream.WriteRPCUnicodeString(HomeDrive);

            stream.WriteShort((short)LogonCount);
            stream.WriteShort((short)BadPasswordCount);

            stream.WriteRid(UserSid);
            stream.WriteRid(GroupSid);

            WriteSidArray(stream, GroupSids);

            if (ExtraSids != null)
            {
                UserFlags |= UserFlags.LOGON_EXTRA_SIDS;
            }

            if (ResourceGroups != null)
            {
                UserFlags |= UserFlags.LOGON_RESOURCE_GROUPS;
            }

            stream.WriteUnsignedInt((int)UserFlags);

            stream.WriteBytes(new byte[16]);

            stream.WriteRPCUnicodeString(ServerName);
            stream.WriteRPCUnicodeString(DomainName);

            stream.WriteSid(DomainSid, "DomainSid");

            stream.WriteBytes(new byte[8]);

            stream.WriteUnsignedInt((int)UserAccountControl);
            stream.WriteUnsignedInt(SubAuthStatus);

            stream.WriteFiletime(LastSuccessfulILogon);
            stream.WriteFiletime(LastFailedILogon);
            stream.WriteUnsignedInt(FailedILogonCount);

            // reserved3
            stream.WriteUnsignedInt(0);

            WriteExtraSids(stream, ExtraSids);

            stream.WriteSid(ResourceDomainSid, "ResourceDomainSid");

            WriteSidArray(stream, ResourceGroups);

            // write GroupSids
            // write DomainSid
            // write ExtraSids
            // write ResourceDomainSid
            // write ResourceGroups
        }

        private void WriteExtraSids(NdrBinaryStream stream, IEnumerable<SecurityIdentifier> extraSids)
        {
            stream.WriteSids(extraSids, "ExtraSids");
        }

        private void WriteSidArray(NdrBinaryStream stream, IEnumerable<SecurityIdentifier> sids)
        {
            stream.WriteRids(sids);
        }

        private static SecurityIdentifier[] ParseExtraSids(NdrBinaryStream Stream, int extraSidCount, int extraSidPointer)
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

        private static IEnumerable<SecurityIdentifier> ParseAttributes(NdrBinaryStream Stream, int count, int pointer)
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

        public override void ReadBody(NdrBinaryStream stream)
        {
            LogonTime = stream.ReadFiletime();
            LogoffTime = stream.ReadFiletime();
            KickOffTime = stream.ReadFiletime();
            PwdLastChangeTime = stream.ReadFiletime();
            PwdCanChangeTime = stream.ReadFiletime();
            PwdMustChangeTime = stream.ReadFiletime();

            var userName = stream.ReadRPCUnicodeString();
            var userDisplayName = stream.ReadRPCUnicodeString();
            var logonScript = stream.ReadRPCUnicodeString();
            var profilePath = stream.ReadRPCUnicodeString();
            var homeDirectory = stream.ReadRPCUnicodeString();
            var homeDrive = stream.ReadRPCUnicodeString();

            LogonCount = stream.ReadShort();
            BadPasswordCount = stream.ReadShort();

            var userSid = stream.ReadRid();
            var groupSid = stream.ReadRid();

            // Groups information
            var groupCount = stream.ReadInt();
            var groupPointer = stream.ReadInt();

            UserFlags = (UserFlags)stream.ReadInt();

            // sessionKey
            stream.Read(new byte[16]);

            var serverNameString = stream.ReadRPCUnicodeString();
            var domainNameString = stream.ReadRPCUnicodeString();
            var domainIdPointer = stream.ReadInt();

            // reserved1
            stream.Read(new byte[8]);

            UserAccountControl = (UserAccountControlFlags)stream.ReadInt();

            SubAuthStatus = stream.ReadInt();
            LastSuccessfulILogon = stream.ReadFiletime();
            LastFailedILogon = stream.ReadFiletime();
            FailedILogonCount = stream.ReadInt();

            // reserved3
            stream.ReadInt();

            // Extra SIDs information
            var extraSidCount = stream.ReadInt();
            var extraSidPointer = stream.ReadInt();

            var resourceDomainIdPointer = stream.ReadInt();
            var resourceGroupCount = stream.ReadInt();
            var resourceGroupPointer = stream.ReadInt();

            UserName = userName.ReadString(stream);
            UserDisplayName = userDisplayName.ReadString(stream);
            LogonScript = logonScript.ReadString(stream);
            ProfilePath = profilePath.ReadString(stream);
            HomeDirectory = homeDirectory.ReadString(stream);
            HomeDrive = homeDrive.ReadString(stream);

            // Groups data
            var groupSids = ParseAttributes(stream, groupCount, groupPointer);

            // Server related strings
            ServerName = serverNameString.ReadString(stream);
            DomainName = domainNameString.ReadString(stream);

            if (domainIdPointer != 0)
            {
                DomainSid = stream.ReadSid();
            }

            UserSid = userSid.AppendTo(DomainSid);
            GroupSid = groupSid.AppendTo(DomainSid);

            GroupSids = groupSids.Select(g => g.AppendTo(DomainSid)).ToList();

            if (UserFlags.HasFlag(UserFlags.LOGON_EXTRA_SIDS))
            {
                ExtraSids = ParseExtraSids(stream, extraSidCount, extraSidPointer).ToList();
            }

            if (resourceDomainIdPointer != 0)
            {
                ResourceDomainSid = stream.ReadSid();
            }

            if (UserFlags.HasFlag(UserFlags.LOGON_RESOURCE_GROUPS))
            {
                ResourceGroups = ParseAttributes(
                    stream,
                    resourceGroupCount,
                    resourceGroupPointer
                ).Select(g => g.AppendTo(ResourceDomainSid)).ToList();
            }
        }

        public DateTimeOffset LogonTime { get; set; }

        public DateTimeOffset LogoffTime { get; set; }

        public DateTimeOffset KickOffTime { get; set; }

        public DateTimeOffset PwdLastChangeTime { get; set; }

        public DateTimeOffset PwdCanChangeTime { get; set; }

        public DateTimeOffset PwdMustChangeTime { get; set; }

        public long LogonCount { get; set; }

        public long BadPasswordCount { get; set; }

        public string UserName { get; set; }

        public string UserDisplayName { get; set; }

        public string LogonScript { get; set; }

        public string ProfilePath { get; set; }

        public string HomeDirectory { get; set; }

        public string HomeDrive { get; set; }

        public string ServerName { get; set; }

        public string DomainName { get; set; }

        public SecurityIdentifier UserSid { get; set; }

        public SecurityIdentifier GroupSid { get; set; }

        public IEnumerable<SecurityIdentifier> GroupSids { get; set; }

        public IEnumerable<SecurityIdentifier> ExtraSids { get; set; }

        public UserAccountControlFlags UserAccountControl { get; set; }

        public UserFlags UserFlags { get; set; }

        public int FailedILogonCount { get; set; }

        public DateTimeOffset LastFailedILogon { get; set; }

        public DateTimeOffset LastSuccessfulILogon { get; set; }

        public int SubAuthStatus { get; set; }

        public SecurityIdentifier ResourceDomainSid { get; set; }

        public IEnumerable<SecurityIdentifier> ResourceGroups { get; set; }

        public SecurityIdentifier DomainSid { get; set; }
    }
}