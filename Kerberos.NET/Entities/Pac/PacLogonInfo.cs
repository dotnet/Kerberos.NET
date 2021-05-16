// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    public partial class PacLogonInfo : NdrPacObject
    {
        private static readonly int[] Reserved1FixedValue = new[] { 0, 0 };
        private static readonly byte[] ReservedSessionKey = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        public PacLogonInfo()
        {
            this.LogonTime = DateTimeOffset.MinValue;
            this.LogoffTime = DateTimeOffset.MinValue;
            this.KickOffTime = DateTimeOffset.MinValue;
            this.PwdLastChangeTime = DateTimeOffset.MinValue;
            this.PwdCanChangeTime = DateTimeOffset.MinValue;
            this.PwdMustChangeTime = DateTimeOffset.MinValue;
            this.LastSuccessfulILogon = DateTimeOffset.MinValue;
            this.LastFailedILogon = DateTimeOffset.MinValue;

            this.Reserved1 = Reserved1FixedValue;
            this.UserSessionKey = ReservedSessionKey;
        }

        public override PacType PacType => PacType.LOGON_INFO;

        public override void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteStruct(this.LogonTime);
            buffer.WriteStruct(this.LogoffTime);
            buffer.WriteStruct(this.KickOffTime);
            buffer.WriteStruct(this.PwdLastChangeTime);
            buffer.WriteStruct(this.PwdCanChangeTime);
            buffer.WriteStruct(this.PwdMustChangeTime);

            buffer.WriteStruct(this.UserName);
            buffer.WriteStruct(this.UserDisplayName);
            buffer.WriteStruct(this.LogonScript);
            buffer.WriteStruct(this.ProfilePath);
            buffer.WriteStruct(this.HomeDirectory);
            buffer.WriteStruct(this.HomeDrive);

            buffer.WriteInt16LittleEndian(this.LogonCount);
            buffer.WriteInt16LittleEndian(this.BadPasswordCount);

            buffer.WriteUInt32LittleEndian(this.UserId);
            buffer.WriteUInt32LittleEndian(this.GroupId);

            buffer.WriteInt32LittleEndian(this.GroupCount);
            buffer.WriteDeferredStructArray(this.GroupIds);

            buffer.WriteInt32LittleEndian((int)this.UserFlags);

            buffer.WriteMemory(this.UserSessionKey);

            buffer.WriteStruct(this.ServerName);
            buffer.WriteStruct(this.DomainName);

            buffer.WriteConformantStruct(this.DomainId);

            buffer.WriteFixedPrimitiveArray(this.Reserved1.Span);

            buffer.WriteInt32LittleEndian((int)this.UserAccountControl);
            buffer.WriteInt32LittleEndian(this.SubAuthStatus);

            buffer.WriteStruct(this.LastSuccessfulILogon);
            buffer.WriteStruct(this.LastFailedILogon);
            buffer.WriteInt32LittleEndian(this.FailedILogonCount);

            buffer.WriteInt32LittleEndian(this.Reserved3);

            buffer.WriteInt32LittleEndian(this.ExtraSidCount);
            buffer.WriteDeferredConformantStructArray(this.ExtraIds);

            buffer.WriteConformantStruct(this.ResourceDomainId);

            buffer.WriteInt32LittleEndian(this.ResourceGroupCount);
            buffer.WriteDeferredStructArray(this.ResourceGroupIds);
        }

        public override void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.LogonTime = buffer.ReadStruct<RpcFileTime>();
            this.LogoffTime = buffer.ReadStruct<RpcFileTime>();
            this.KickOffTime = buffer.ReadStruct<RpcFileTime>();
            this.PwdLastChangeTime = buffer.ReadStruct<RpcFileTime>();
            this.PwdCanChangeTime = buffer.ReadStruct<RpcFileTime>();
            this.PwdMustChangeTime = buffer.ReadStruct<RpcFileTime>();

            this.UserName = buffer.ReadStruct<RpcString>();
            this.UserDisplayName = buffer.ReadStruct<RpcString>();
            this.LogonScript = buffer.ReadStruct<RpcString>();
            this.ProfilePath = buffer.ReadStruct<RpcString>();
            this.HomeDirectory = buffer.ReadStruct<RpcString>();
            this.HomeDrive = buffer.ReadStruct<RpcString>();

            this.LogonCount = buffer.ReadInt16LittleEndian();
            this.BadPasswordCount = buffer.ReadInt16LittleEndian();

            this.UserId = buffer.ReadUInt32LittleEndian();
            this.GroupId = buffer.ReadUInt32LittleEndian();

            var groupCount = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<GroupMembership>(groupCount, v => this.GroupIds = v);

            this.UserFlags = (UserFlags)buffer.ReadInt32LittleEndian();

            this.UserSessionKey = buffer.ReadMemory(16);

            this.ServerName = buffer.ReadStruct<RpcString>();
            this.DomainName = buffer.ReadStruct<RpcString>();

            buffer.ReadConformantStruct<RpcSid>(v => this.DomainId = v);

            this.Reserved1 = buffer.ReadFixedPrimitiveArray<int>(2).ToArray();

            this.UserAccountControl = (UserAccountControlFlags)buffer.ReadInt32LittleEndian();
            this.SubAuthStatus = buffer.ReadInt32LittleEndian();
            this.LastSuccessfulILogon = buffer.ReadStruct<RpcFileTime>();
            this.LastFailedILogon = buffer.ReadStruct<RpcFileTime>();
            this.FailedILogonCount = buffer.ReadInt32LittleEndian();

            this.Reserved3 = buffer.ReadInt32LittleEndian();

            var extraSidsCount = buffer.ReadInt32LittleEndian();
            buffer.ReadDeferredStructArray<RpcSidAttributes>(extraSidsCount, v => this.ExtraIds = v);

            buffer.ReadConformantStruct<RpcSid>(v => this.ResourceDomainId = v);

            var resourceGroupCount = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<GroupMembership>(resourceGroupCount, v => this.ResourceGroupIds = v);
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

        public int GroupCount => this.GroupIds?.Count() ?? 0;

        // [SizeIs("GroupCount")]
        public IEnumerable<GroupMembership> GroupIds { get; set; }

        public UserFlags UserFlags { get; set; }

        public ReadOnlyMemory<byte> UserSessionKey { get; set; }

        public RpcString ServerName { get; set; } = RpcString.Empty;

        public RpcString DomainName { get; set; } = RpcString.Empty;

        public RpcSid DomainId { get; set; }

        // [FixedSize(2)]
        public ReadOnlyMemory<int> Reserved1 { get; set; }

        public UserAccountControlFlags UserAccountControl { get; set; }

        public int SubAuthStatus { get; set; }

        public RpcFileTime LastSuccessfulILogon { get; set; }

        public RpcFileTime LastFailedILogon { get; set; }

        public int FailedILogonCount { get; set; }

        public int Reserved3 { get; set; }

        public int ExtraSidCount => this.ExtraIds?.Count() ?? 0;

        // [SizeIs("ExtraSidCount")]
        public IEnumerable<RpcSidAttributes> ExtraIds { get; set; }

        public RpcSid ResourceDomainId { get; set; }

        public int ResourceGroupCount => this.ResourceGroupIds?.Count() ?? 0;

        // [SizeIs("ResourceGroupCount")]
        public IEnumerable<GroupMembership> ResourceGroupIds { get; set; }

        public SecurityIdentifier UserSid
        {
            get => SecurityIdentifier.FromRpcSid(this.DomainId, this.UserId);
            set => this.UserId = value?.Id ?? 0;
        }

        public SecurityIdentifier GroupSid
        {
            get => SecurityIdentifier.FromRpcSid(this.DomainId, this.GroupId);
            set => this.GroupId = value?.Id ?? 0;
        }

        private static readonly IEnumerable<SecurityIdentifier> EmptySid = Array.Empty<SecurityIdentifier>();

        public IEnumerable<SecurityIdentifier> GroupSids
            => this.GroupIds?.Select(g => SecurityIdentifier.FromRpcSid(this.DomainId, g.RelativeId, g.Attributes)) ?? EmptySid;

        public IEnumerable<SecurityIdentifier> ExtraSids
            => this.ExtraIds?.Select(g => g.ToSecurityIdentifier()) ?? EmptySid;

        public SecurityIdentifier ResourceDomainSid
            => this.ResourceDomainId?.ToSecurityIdentifier();

        public IEnumerable<SecurityIdentifier> ResourceGroups
            => this.ResourceGroupIds?.Select(g => SecurityIdentifier.FromRpcSid(this.ResourceDomainId, g.RelativeId, g.Attributes)) ?? EmptySid;

        public SecurityIdentifier DomainSid
        {
            get => this.DomainId.ToSecurityIdentifier();
            set => this.DomainId = value?.ToRpcSid();
        }
    }
}
