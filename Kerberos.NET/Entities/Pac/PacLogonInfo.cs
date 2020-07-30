using Kerberos.NET.Ndr;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Entities.Pac
{
    public partial class PacLogonInfo : NdrPacObject
    {
        private static readonly int[] Reserved1FixedValue = new[] { 0, 0 };
        private static readonly byte[] ReservedSessionKey = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        public PacLogonInfo()
        {
            LogonTime = DateTimeOffset.MinValue;
            LogoffTime = DateTimeOffset.MinValue;
            KickOffTime = DateTimeOffset.MinValue;
            PwdLastChangeTime = DateTimeOffset.MinValue;
            PwdCanChangeTime = DateTimeOffset.MinValue;
            PwdMustChangeTime = DateTimeOffset.MinValue;
            LastSuccessfulILogon = DateTimeOffset.MinValue;
            LastFailedILogon = DateTimeOffset.MinValue;

            Reserved1 = Reserved1FixedValue;
            UserSessionKey = ReservedSessionKey;
        }

        public override PacType PacType => PacType.LOGON_INFO;

        public override void Marshal(NdrBuffer buffer)
        {
            buffer.WriteStruct(LogonTime);
            buffer.WriteStruct(LogoffTime);
            buffer.WriteStruct(KickOffTime);
            buffer.WriteStruct(PwdLastChangeTime);
            buffer.WriteStruct(PwdCanChangeTime);
            buffer.WriteStruct(PwdMustChangeTime);

            buffer.WriteStruct(UserName);
            buffer.WriteStruct(UserDisplayName);
            buffer.WriteStruct(LogonScript);
            buffer.WriteStruct(ProfilePath);
            buffer.WriteStruct(HomeDirectory);
            buffer.WriteStruct(HomeDrive);

            buffer.WriteInt16LittleEndian(LogonCount);
            buffer.WriteInt16LittleEndian(BadPasswordCount);

            buffer.WriteUInt32LittleEndian(UserId);
            buffer.WriteUInt32LittleEndian(GroupId);

            buffer.WriteInt32LittleEndian(GroupCount);
            buffer.WriteDeferredStructArray(GroupIds);

            buffer.WriteInt32LittleEndian((int)UserFlags);

            buffer.WriteMemory(UserSessionKey);

            buffer.WriteStruct(ServerName);
            buffer.WriteStruct(DomainName);

            buffer.WriteConformantStruct(DomainId);

            buffer.WriteFixedPrimitiveArray(Reserved1.Span);

            buffer.WriteInt32LittleEndian((int)UserAccountControl);
            buffer.WriteInt32LittleEndian(SubAuthStatus);

            buffer.WriteStruct(LastSuccessfulILogon);
            buffer.WriteStruct(LastFailedILogon);
            buffer.WriteInt32LittleEndian(FailedILogonCount);

            buffer.WriteInt32LittleEndian(Reserved3);

            buffer.WriteInt32LittleEndian(ExtraSidCount);
            buffer.WriteDeferredConformantStructArray(ExtraIds);

            buffer.WriteConformantStruct(ResourceDomainId);

            buffer.WriteInt32LittleEndian(ResourceGroupCount);
            buffer.WriteDeferredStructArray(ResourceGroupIds);
        }

        public override void Unmarshal(NdrBuffer buffer)
        {
            LogonTime = buffer.ReadStruct<RpcFileTime>();
            LogoffTime = buffer.ReadStruct<RpcFileTime>();
            KickOffTime = buffer.ReadStruct<RpcFileTime>();
            PwdLastChangeTime = buffer.ReadStruct<RpcFileTime>();
            PwdCanChangeTime = buffer.ReadStruct<RpcFileTime>();
            PwdMustChangeTime = buffer.ReadStruct<RpcFileTime>();

            UserName = buffer.ReadStruct<RpcString>();
            UserDisplayName = buffer.ReadStruct<RpcString>();
            LogonScript = buffer.ReadStruct<RpcString>();
            ProfilePath = buffer.ReadStruct<RpcString>();
            HomeDirectory = buffer.ReadStruct<RpcString>();
            HomeDrive = buffer.ReadStruct<RpcString>();

            LogonCount = buffer.ReadInt16LittleEndian();
            BadPasswordCount = buffer.ReadInt16LittleEndian();

            UserId = buffer.ReadUInt32LittleEndian();
            GroupId = buffer.ReadUInt32LittleEndian();

            var groupCount = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<GroupMembership>(groupCount, v => GroupIds = v);

            UserFlags = (UserFlags)buffer.ReadInt32LittleEndian();

            UserSessionKey = buffer.ReadMemory(16);

            ServerName = buffer.ReadStruct<RpcString>();
            DomainName = buffer.ReadStruct<RpcString>();

            buffer.ReadConformantStruct<RpcSid>(v => DomainId = v);

            Reserved1 = buffer.ReadFixedPrimitiveArray<int>(2).ToArray();

            UserAccountControl = (UserAccountControlFlags)buffer.ReadInt32LittleEndian();
            SubAuthStatus = buffer.ReadInt32LittleEndian();
            LastSuccessfulILogon = buffer.ReadStruct<RpcFileTime>();
            LastFailedILogon = buffer.ReadStruct<RpcFileTime>();
            FailedILogonCount = buffer.ReadInt32LittleEndian();

            Reserved3 = buffer.ReadInt32LittleEndian();

            var extraSidsCount = buffer.ReadInt32LittleEndian();
            buffer.ReadDeferredStructArray<RpcSidAttributes>(extraSidsCount, v => ExtraIds = v);

            buffer.ReadConformantStruct<RpcSid>(v => ResourceDomainId = v);

            var resourceGroupCount = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<GroupMembership>(resourceGroupCount, v => ResourceGroupIds = v);
        }

        public RpcFileTime LogonTime { get; set; }

        public RpcFileTime LogoffTime { get; set; }

        public RpcFileTime KickOffTime { get; set; }

        public RpcFileTime PwdLastChangeTime { get; set; }

        public RpcFileTime PwdCanChangeTime { get; set; }

        public RpcFileTime PwdMustChangeTime { get; set; }

        public RpcString UserName { get; set; } = RpcString.Empty;

        public RpcString UserDisplayName { get; set; } = RpcString.Empty;

        public RpcString LogonScript { get; set; } = RpcString.Empty;

        public RpcString ProfilePath { get; set; } = RpcString.Empty;

        public RpcString HomeDirectory { get; set; } = RpcString.Empty;

        public RpcString HomeDrive { get; set; } = RpcString.Empty;

        public short LogonCount { get; set; }

        public short BadPasswordCount { get; set; }

        public uint UserId { get; set; }

        public uint GroupId { get; set; }

        public int GroupCount => GroupIds?.Count() ?? 0;

        //[SizeIs("GroupCount")]
        [KerberosIgnore]
        public IEnumerable<GroupMembership> GroupIds { get; set; }

        public UserFlags UserFlags { get; set; }

        public ReadOnlyMemory<byte> UserSessionKey { get; set; }

        public RpcString ServerName { get; set; } = RpcString.Empty;

        public RpcString DomainName { get; set; } = RpcString.Empty;

        [KerberosIgnore]
        public RpcSid DomainId { get; set; }

        //[FixedSize(2)]
        public ReadOnlyMemory<int> Reserved1 { get; set; }

        public UserAccountControlFlags UserAccountControl { get; set; }

        public int SubAuthStatus { get; set; }

        public RpcFileTime LastSuccessfulILogon { get; set; }

        public RpcFileTime LastFailedILogon { get; set; }

        public int FailedILogonCount { get; set; }

        public int Reserved3 { get; set; }

        public int ExtraSidCount => ExtraIds?.Count() ?? 0;

        //[SizeIs("ExtraSidCount")]
        [KerberosIgnore]
        public IEnumerable<RpcSidAttributes> ExtraIds { get; set; }

        public RpcSid ResourceDomainId { get; set; }

        public int ResourceGroupCount => ResourceGroupIds?.Count() ?? 0;

        //[SizeIs("ResourceGroupCount")]
        [KerberosIgnore]
        public IEnumerable<GroupMembership> ResourceGroupIds { get; set; }

        public SecurityIdentifier UserSid
        {
            get => SecurityIdentifier.FromRpcSid(DomainId, UserId);
            set => UserId = value.Id;
        }

        public SecurityIdentifier GroupSid
        {
            get => SecurityIdentifier.FromRpcSid(DomainId, GroupId);
            set => GroupId = value.Id;
        }

        private static readonly IEnumerable<SecurityIdentifier> EmptySid = Array.Empty<SecurityIdentifier>();

        public IEnumerable<SecurityIdentifier> GroupSids
            => GroupIds?.Select(g => SecurityIdentifier.FromRpcSid(DomainId, g.RelativeId, g.Attributes)) ?? EmptySid;

        public IEnumerable<SecurityIdentifier> ExtraSids
            => ExtraIds?.Select(g => g.Sid.ToSecurityIdentifier()) ?? EmptySid;

        public SecurityIdentifier ResourceDomainSid
            => ResourceDomainId?.ToSecurityIdentifier();

        public IEnumerable<SecurityIdentifier> ResourceGroups
            => ResourceGroupIds?.Select(g => SecurityIdentifier.FromRpcSid(ResourceDomainId, g.RelativeId, g.Attributes)) ?? EmptySid;

        public SecurityIdentifier DomainSid
        {
            get => DomainId.ToSecurityIdentifier();
            set => DomainId = value.ToRpcSid();
        }
    }
}
