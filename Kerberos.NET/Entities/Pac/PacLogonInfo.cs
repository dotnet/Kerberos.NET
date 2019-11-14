using Kerberos.NET.Ndr;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Entities.Pac
{
    public partial class PacLogonInfo : NdrPacObject, IPacElement
    {
        private static readonly int[] Reserved1FixedValue = new[] { 0, 0 };
        private static readonly byte[] ReservedSessionKey = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        public PacLogonInfo()
        {
            Reserved1 = Reserved1FixedValue;
            UserSessionKey = ReservedSessionKey;
        }

        public PacType PacType => PacType.LOGON_INFO;

        public override void Marshal(NdrBuffer buffer)
        {
            buffer.WriteFiletime(LogonTime);
            buffer.WriteFiletime(LogoffTime);
            buffer.WriteFiletime(KickOffTime);
            buffer.WriteFiletime(PwdLastChangeTime);
            buffer.WriteFiletime(PwdCanChangeTime);
            buffer.WriteFiletime(PwdMustChangeTime);

            buffer.WriteStruct(UserName);
            buffer.WriteStruct(UserDisplayName);
            buffer.WriteStruct(LogonScript);
            buffer.WriteStruct(ProfilePath);
            buffer.WriteStruct(HomeDirectory);
            buffer.WriteStruct(HomeDrive);

            buffer.WriteInt16LittleEndian(LogonCount);
            buffer.WriteInt16LittleEndian(BadPasswordCount);

            buffer.WriteInt32LittleEndian(UserId);
            buffer.WriteInt32LittleEndian(GroupId);

            buffer.WriteInt32LittleEndian(GroupCount);
            buffer.WriteDeferredStructArray(GroupIds);

            buffer.WriteInt32LittleEndian((int)UserFlags);

            buffer.WriteMemory(UserSessionKey);

            buffer.WriteStruct(ServerName);
            buffer.WriteStruct(DomainName);

            buffer.WriteDeferredStruct(DomainId);

            buffer.WriteFixedPrimitiveArray(Reserved1);

            buffer.WriteInt32LittleEndian((int)UserAccountControl);
            buffer.WriteInt32LittleEndian(SubAuthStatus);

            buffer.WriteFiletime(LastSuccessfulILogon);
            buffer.WriteFiletime(LastFailedILogon);
            buffer.WriteInt32LittleEndian(FailedILogonCount);

            buffer.WriteInt32LittleEndian(Reserved3);

            buffer.WriteInt32LittleEndian(ExtraSidCount);
            buffer.WriteDeferredStructArray(ExtraIds);

            buffer.WriteDeferredStruct(ResourceDomainId);

            buffer.WriteInt32LittleEndian(ResourceGroupCount);
            buffer.WriteDeferredStructArray(ResourceGroupIds);
        }

        public override void Unmarshal(NdrBuffer buffer)
        {
            LogonTime = buffer.ReadFiletime();
            LogoffTime = buffer.ReadFiletime();
            KickOffTime = buffer.ReadFiletime();
            PwdLastChangeTime = buffer.ReadFiletime();
            PwdCanChangeTime = buffer.ReadFiletime();
            PwdMustChangeTime = buffer.ReadFiletime();

            UserName = buffer.ReadStruct<RpcString>();
            UserDisplayName = buffer.ReadStruct<RpcString>();
            LogonScript = buffer.ReadStruct<RpcString>();
            ProfilePath = buffer.ReadStruct<RpcString>();
            HomeDirectory = buffer.ReadStruct<RpcString>();
            HomeDrive = buffer.ReadStruct<RpcString>();

            LogonCount = buffer.ReadInt16LittleEndian();
            BadPasswordCount = buffer.ReadInt16LittleEndian();

            UserId = buffer.ReadInt32LittleEndian();
            GroupId = buffer.ReadInt32LittleEndian();

            var groupCount = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<GroupMembership>(groupCount, v => GroupIds = v);

            UserFlags = (UserFlags)buffer.ReadInt32LittleEndian();

            UserSessionKey = buffer.ReadMemory(16);

            ServerName = buffer.ReadStruct<RpcString>();
            DomainName = buffer.ReadStruct<RpcString>();
            buffer.ReadDeferredStruct<RpcSid>(v => DomainId = v);

            Reserved1 = buffer.ReadFixedPrimitiveArray<int>(2).ToArray();

            UserAccountControl = (UserAccountControlFlags)buffer.ReadInt32LittleEndian();
            SubAuthStatus = buffer.ReadInt32LittleEndian();
            LastSuccessfulILogon = buffer.ReadFiletime();
            LastFailedILogon = buffer.ReadFiletime();
            FailedILogonCount = buffer.ReadInt32LittleEndian();

            Reserved3 = buffer.ReadInt32LittleEndian();

            var extraSidsCount = buffer.ReadInt32LittleEndian();
            buffer.ReadDeferredStructArray<RpcSidAttributes>(extraSidsCount, v => ExtraIds = v);

            buffer.ReadDeferredStruct<RpcSid>(v => ResourceDomainId = v);

            var resourceGroupCount = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<GroupMembership>(resourceGroupCount, v => ResourceGroupIds = v);
        }

        public DateTimeOffset LogonTime { get; set; }

        public DateTimeOffset LogoffTime { get; set; }

        public DateTimeOffset KickOffTime { get; set; }

        public DateTimeOffset PwdLastChangeTime { get; set; }

        public DateTimeOffset PwdCanChangeTime { get; set; }

        public DateTimeOffset PwdMustChangeTime { get; set; }

        public RpcString UserName { get; set; } = RpcString.Empty;

        public RpcString UserDisplayName { get; set; } = RpcString.Empty;

        public RpcString LogonScript { get; set; } = RpcString.Empty;

        public RpcString ProfilePath { get; set; } = RpcString.Empty;

        public RpcString HomeDirectory { get; set; } = RpcString.Empty;

        public RpcString HomeDrive { get; set; } = RpcString.Empty;

        public short LogonCount { get; set; }

        public short BadPasswordCount { get; set; }

        public int UserId { get; set; }

        public int GroupId { get; set; }

        public int GroupCount => GroupIds?.Count() ?? 0;

        //[SizeIs("GroupCount")]
        public IEnumerable<GroupMembership> GroupIds { get; set; }

        public UserFlags UserFlags { get; set; }

        public ReadOnlyMemory<byte> UserSessionKey { get; set; }

        public RpcString ServerName { get; set; } = RpcString.Empty;

        public RpcString DomainName { get; set; } = RpcString.Empty;

        public RpcSid DomainId { get; set; }

        //[FixedSize(2)]
        public int[] Reserved1 { get; set; }

        public UserAccountControlFlags UserAccountControl { get; set; }

        public int SubAuthStatus { get; set; }

        public DateTimeOffset LastSuccessfulILogon { get; set; }

        public DateTimeOffset LastFailedILogon { get; set; }

        public int FailedILogonCount { get; set; }

        public int Reserved3 { get; set; }

        public int ExtraSidCount => ExtraIds?.Count() ?? 0;

        //[SizeIs("ExtraSidCount")]
        public IEnumerable<RpcSidAttributes> ExtraIds { get; set; }

        public RpcSid ResourceDomainId { get; set; }

        public int ResourceGroupCount => ResourceGroupIds?.Count() ?? 0;

        //[SizeIs("ResourceGroupCount")]
        public IEnumerable<GroupMembership> ResourceGroupIds { get; set; }

        public SecurityIdentifier UserSid
        {
            get => new SecurityIdentifier(DomainId, UserId);
            set => UserId = value.SubAuthorities[value.SubAuthorities.Length - 1];
        }

        public SecurityIdentifier GroupSid
        {
            get => new SecurityIdentifier(DomainId, GroupId);
            set => GroupId = value.SubAuthorities[value.SubAuthorities.Length - 1];
        }

        private static readonly IEnumerable<SecurityIdentifier> EmptySid = new SecurityIdentifier[0];

        public IEnumerable<SecurityIdentifier> GroupSids => GroupIds?.Select(g => new SecurityIdentifier(DomainId, g.RelativeId, g.Attributes)) ?? EmptySid;

        public IEnumerable<SecurityIdentifier> ExtraSids => ExtraIds?.Select(g => new SecurityIdentifier(g.Sid)) ?? EmptySid;

        public SecurityIdentifier ResourceDomainSid => ResourceDomainId != null ? new SecurityIdentifier(ResourceDomainId) : null;

        public IEnumerable<SecurityIdentifier> ResourceGroups => ResourceGroupIds?.Select(g => new SecurityIdentifier(ResourceDomainId, g.RelativeId, g.Attributes)) ?? EmptySid;

        public SecurityIdentifier DomainSid
        {
            get => new SecurityIdentifier(DomainId);
            set => DomainId = value.FromSid();
        }
    }
}
