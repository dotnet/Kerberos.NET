// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.ComponentModel;
using System.Globalization;
using System.Text;

namespace Kerberos.NET.Entities.Pac
{
    public class SecurityIdentifier
    {
        public static class WellKnown
        {
            public static readonly SecurityIdentifier ThisOrganizationCertificate
                = new SecurityIdentifier(IdentifierAuthority.NTAuthority, new uint[] { 65, 1 }, SidAttributes.SE_GROUP_ENABLED);
        }

        private readonly IdentifierAuthority authority;
        private readonly uint[] subAuthorities;

        private string sddl;

        public SecurityIdentifier(IdentifierAuthority authority, uint[] subs, SidAttributes attributes)
        {
            this.authority = authority;
            this.subAuthorities = subs;

            this.Attributes = attributes;
        }

        public SecurityIdentifier(SecurityIdentifier sub, uint id)
            : this(sub?.authority ?? 0, Concat(sub?.subAuthorities, id), sub.Attributes)
        {
        }

        public static SecurityIdentifier FromRpcSid(RpcSid sid, uint id = 0, SidAttributes attributes = 0)
        {
            if (sid == null)
            {
                throw new ArgumentNullException(nameof(sid));
            }

            return new SecurityIdentifier(sid.IdentifierAuthority.Authority, Concat(sid.SubAuthority, id), attributes);
        }

        public uint Id => this.subAuthorities.Length > 0 ? this.subAuthorities[this.subAuthorities.Length - 1] : 0;

        public SidAttributes Attributes { get; }

        public string Value => this.ToString();

        public override string ToString()
        {
            if (this.sddl == null)
            {
                var result = new StringBuilder();

                result.AppendFormat(CultureInfo.InvariantCulture, "S-1-{0}", (long)this.authority);

                for (int i = 0; i < this.subAuthorities.Length; i++)
                {
                    result.AppendFormat(CultureInfo.InvariantCulture, "-{0}", this.subAuthorities[i]);
                }

                this.sddl = result.ToString().ToUpperInvariant();
            }

            return this.sddl;
        }

        public RpcSid ToRpcSid()
        {
            var sid = new RpcSid
            {
                Revision = 1,

                IdentifierAuthority = new RpcSidIdentifierAuthority
                {
                    IdentifierAuthority = new byte[] { 0, 0, 0, 0, 0, (byte)this.authority }
                },

                SubAuthority = this.subAuthorities,
                SubAuthorityCount = (byte)this.subAuthorities.Length
            };

            return sid;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
            {
                return false;
            }

            if (obj is SecurityIdentifier sid)
            {
                return string.Equals(this.ToString(), sid.ToString(), StringComparison.InvariantCultureIgnoreCase);
            }

            return base.Equals(obj);
        }

        public override int GetHashCode()
        {
            return this.ToString().GetHashCode();
        }

        private static uint[] Concat(ReadOnlyMemory<uint> subAuthority, uint id)
        {
            uint[] final;

            if (id != 0)
            {
                final = new uint[subAuthority.Length + 1];

                final[final.Length - 1] = id;
            }
            else
            {
                final = new uint[subAuthority.Length];
            }

            subAuthority.Span.CopyTo(final);

            return final;
        }
    }

    [Flags]
    public enum SidAttributes : uint
    {
        [Description("Mandatory Group")]
        SE_GROUP_MANDATORY = 0x00000001,

        [Description("Enabled by Default")]
        SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002,

        [Description("Group Enabled")]
        SE_GROUP_ENABLED = 0x00000004,

        [Description("Owner")]
        SE_GROUP_OWNER = 0x00000008,

        [Description("Deny Only")]
        SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010,

        [Description("Integrity")]
        SE_GROUP_INTEGRITY = 0x00000020,

        [Description("Integrity Enabled")]
        SE_GROUP_INTEGRITY_ENABLED = 0x00000040,

        [Description("Group Resource")]
        SE_GROUP_RESOURCE = 0x20000000,

        [Description("Logon Id")]
        SE_GROUP_LOGON_ID = 0xC0000000
    }

    public enum IdentifierAuthority
    {
        NullAuthority = 0,
        WorldAuthority = 1,
        LocalAuthority = 2,
        CreatorAuthority = 3,
        NonUniqueAuthority = 4,
        NTAuthority = 5,
        SiteServerAuthority = 6,
        InternetSiteAuthority = 7,
        ExchangeAuthority = 8,
        ResourceManagerAuthority = 9,
        PassportAuthority = 10,
        InternetAuthority = 11,
        AadAuthority = 12,
        AppPackageAuthority = 15,
        MandatoryLabelAuthority = 16,
        ScopedPolicyIdAuthority = 17,
        AuthenticationAuthority = 18
    }
}
