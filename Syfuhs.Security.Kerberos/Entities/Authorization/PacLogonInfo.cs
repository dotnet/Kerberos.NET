using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace Syfuhs.Security.Kerberos.Entities.Authorization
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
        {
            var pacStream = new NdrBinaryReader(node);

            Header = new RpcHeader(pacStream);

            LogonTime = pacStream.ReadFiletime();
            LogoffTime = pacStream.ReadFiletime();
            KickOffTime = pacStream.ReadFiletime();
            PwdLastChangeTime = pacStream.ReadFiletime();
            PwdCanChangeTime = pacStream.ReadFiletime();
            PwdMustChangeTime = pacStream.ReadFiletime();

            var userName = pacStream.ReadRPCUnicodeString();
            var userDisplayName = pacStream.ReadRPCUnicodeString();
            var logonScript = pacStream.ReadRPCUnicodeString();
            var profilePath = pacStream.ReadRPCUnicodeString();
            var homeDirectory = pacStream.ReadRPCUnicodeString();
            var homeDrive = pacStream.ReadRPCUnicodeString();

            LogonCount = pacStream.ReadShort();
            BadPasswordCount = pacStream.ReadShort();

            var userSid = pacStream.ReadRid();
            var groupSid = pacStream.ReadRid();

            // Groups information
            var groupCount = pacStream.ReadInt();
            var groupPointer = pacStream.ReadInt();

            UserFlags = (UserFlags)pacStream.ReadInt();

            // sessionKey
            pacStream.Read(new byte[16]);

            var serverNameString = pacStream.ReadRPCUnicodeString();
            var domainNameString = pacStream.ReadRPCUnicodeString();
            var domainIdPointer = pacStream.ReadInt();

            // reserved1
            pacStream.Read(new byte[8]);

            UserAccountControl = (UserAccountControlFlags)pacStream.ReadInt();

            SubAuthStatus = pacStream.ReadInt();
            LastSuccessfulILogon = pacStream.ReadFiletime();
            LastFailedILogon = pacStream.ReadFiletime();
            FailedILogonCount = pacStream.ReadInt();

            // reserved3
            pacStream.ReadInt();

            // Extra SIDs information
            var extraSidCount = pacStream.ReadInt();
            var extraSidPointer = pacStream.ReadInt();

            var resourceDomainIdPointer = pacStream.ReadInt();
            var resourceGroupCount = pacStream.ReadInt();
            var resourceGroupPointer = pacStream.ReadInt();

            UserName = userName.ReadString(pacStream);
            UserDisplayName = userDisplayName.ReadString(pacStream);
            LogonScript = logonScript.ReadString(pacStream);
            ProfilePath = profilePath.ReadString(pacStream);
            HomeDirectory = homeDirectory.ReadString(pacStream);
            HomeDrive = homeDrive.ReadString(pacStream);

            // Groups data
            var groupSids = ParseAttributes(pacStream, groupCount, groupPointer);

            // Server related strings
            ServerName = serverNameString.ReadString(pacStream);
            DomainName = domainNameString.ReadString(pacStream);

            if (domainIdPointer != 0)
            {
                DomainSid = pacStream.ReadSid();
            }

            UserSid = Merge(userSid, DomainSid);
            GroupSid = Merge(groupSid, DomainSid);

            GroupSids = groupSids.Select(g => Merge(g, DomainSid)).ToList();

            if (UserFlags.HasFlag(UserFlags.LOGON_EXTRA_SIDS))
            {
                ExtraSids = ParseExtraSids(pacStream, extraSidCount, extraSidPointer).Select(e => Merge(e.Id, DomainSid)).ToList();
            }

            if (resourceDomainIdPointer != 0)
            {
                ResourceDomainSid = pacStream.ReadSid();
            }

            if (UserFlags.HasFlag(UserFlags.LOGON_RESOURCE_GROUPS))
            {
                ResourceGroups = ParseAttributes(
                    pacStream,
                    resourceGroupCount,
                    resourceGroupPointer
                ).Select(g => Merge(g, DomainSid)).ToList();
            }
        }

        private class SidParts
        {
            public int Revision { get; set; }

            public int Count { get; set; }

            public byte[] Authority { get; set; }

            public byte[] Subs { get; set; }

            public SidParts() { }

            public SidParts(SecurityIdentifier sid)
            {
                var bytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(bytes, 0);

                Revision = bytes[0];
                Count = bytes[1];
                Authority = new byte[6];

                Buffer.BlockCopy(bytes, 2, Authority, 0, 6);
                Subs = new byte[bytes.Length - 8];

                Buffer.BlockCopy(bytes, 8, Subs, 0, bytes.Length - 8);
            }
        }

        private SecurityIdentifier Merge(SecurityIdentifier ridId, SecurityIdentifier sidId)
        {
            var rid = new SidParts(ridId);
            var sid = new SidParts(sidId);

            var count = sid.Count + rid.Count;
            var subs = new byte[count * 4];

            Buffer.BlockCopy(sid.Subs, 0, subs, 0, sid.Subs.Length);
            Buffer.BlockCopy(rid.Subs, 0, subs, sid.Subs.Length, rid.Subs.Length);

            var bytes = new byte[8 + count * 4];

            bytes[0] = (byte)sid.Revision;
            bytes[1] = (byte)count;

            Buffer.BlockCopy(sid.Authority, 0, bytes, 2, 6);
            Buffer.BlockCopy(subs, 0, bytes, 8, subs.Length);

            return new SecurityIdentifier(bytes, 0);
        }

        private static PacSid[] ParseExtraSids(NdrBinaryReader pacStream, int extraSidCount, int extraSidPointer)
        {
            if (extraSidPointer == 0)
            {
                return new PacSid[0];
            }

            int realExtraSidCount = pacStream.ReadInt();

            if (realExtraSidCount != extraSidCount)
            {
                throw new InvalidDataException($"Expected Sid count {extraSidCount} doesn't match actual sid count {realExtraSidCount}");
            }

            var extraSidAtts = new PacSid[extraSidCount];

            var pointers = new int[extraSidCount];
            var attributes = new SidAttributes[extraSidCount];

            for (int i = 0; i < extraSidCount; i++)
            {
                pointers[i] = pacStream.ReadInt();
                attributes[i] = (SidAttributes)pacStream.ReadUnsignedInt();
            }

            for (int i = 0; i < extraSidCount; i++)
            {
                SecurityIdentifier sid = null;

                if (pointers[i] != 0)
                {
                    sid = pacStream.ReadSid();
                }

                extraSidAtts[i] = new PacSid(sid, attributes[i]);
            }

            return extraSidAtts;
        }

        private static IEnumerable<SecurityIdentifier> ParseAttributes(NdrBinaryReader pacStream, int count, int pointer)
        {
            var attributes = new List<SecurityIdentifier>();

            if (pointer == 0)
            {
                return attributes;
            }

            int realCount = pacStream.ReadInt();

            if (realCount != count)
            {
                throw new InvalidDataException($"Expected count {count} doesn't match actual count {realCount}");
            }

            for (int i = 0; i < count; i++)
            {
                pacStream.Align(4);

                attributes.Add(pacStream.ReadRid());
                var attr = (SidAttributes)pacStream.ReadInt();
            }

            return attributes;
        }

        public DateTimeOffset LogonTime { get; private set; }

        public DateTimeOffset LogoffTime { get; private set; }

        public DateTimeOffset KickOffTime { get; private set; }

        public DateTimeOffset PwdLastChangeTime { get; private set; }

        public DateTimeOffset PwdCanChangeTime { get; private set; }

        public DateTimeOffset PwdMustChangeTime { get; private set; }

        public long LogonCount { get; private set; }

        public long BadPasswordCount { get; private set; }

        public string UserName { get; private set; }

        public string UserDisplayName { get; private set; }

        public string LogonScript { get; private set; }

        public string ProfilePath { get; private set; }

        public string HomeDirectory { get; private set; }

        public string HomeDrive { get; private set; }

        public string ServerName { get; private set; }

        public string DomainName { get; private set; }

        public SecurityIdentifier UserSid { get; private set; }

        public SecurityIdentifier GroupSid { get; private set; }

        public IEnumerable<SecurityIdentifier> GroupSids { get; private set; }

        public IEnumerable<SecurityIdentifier> ExtraSids { get; private set; }

        public UserAccountControlFlags UserAccountControl { get; private set; }

        public UserFlags UserFlags { get; private set; }

        public int FailedILogonCount { get; private set; }

        public DateTimeOffset LastFailedILogon { get; private set; }

        public DateTimeOffset LastSuccessfulILogon { get; private set; }

        public int SubAuthStatus { get; private set; }

        public SecurityIdentifier ResourceDomainSid { get; private set; }

        public IEnumerable<SecurityIdentifier> ResourceGroups { get; private set; }

        public SecurityIdentifier DomainSid { get; private set; }
    }
}