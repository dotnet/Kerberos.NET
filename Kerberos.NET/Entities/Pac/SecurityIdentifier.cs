using System;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities.Pac
{
    public class SecurityIdentifier
    {
        private readonly IdentifierAuthority authority;
        private readonly uint[] subAuthorities;

        private string sddl;

        public SecurityIdentifier(IdentifierAuthority authority, uint[] subs, SidAttributes attributes)
        {
            this.authority = authority;
            subAuthorities = subs;

            Attributes = attributes;
        }

        public SecurityIdentifier(SecurityIdentifier sub, uint id)
            : this(sub.authority, Concat(sub.subAuthorities, id), sub.Attributes)
        {

        }

        public static SecurityIdentifier FromRpcSid(RpcSid sid, uint id = 0, SidAttributes attributes = 0)
        {
            return new SecurityIdentifier(sid.IdentifierAuthority.Authority, Concat(sid.SubAuthority, id), attributes);
        }

        public uint Id => subAuthorities.Length > 0 ? subAuthorities[subAuthorities.Length - 1] : 0;

        public SidAttributes Attributes { get; }

        public string Value { get { return ToString(); } }

        public override string ToString()
        {
            if (sddl == null)
            {
                var result = new StringBuilder();

                result.AppendFormat("S-1-{0}", (long)authority);

                for (int i = 0; i < subAuthorities.Length; i++)
                {
                    result.AppendFormat("-{0}", subAuthorities[i]);
                }

                sddl = result.ToString().ToUpperInvariant();
            }

            return sddl;
        }

        public RpcSid ToRpcSid()
        {
            var sid = new RpcSid
            {
                Revision = 1,

                IdentifierAuthority = new RpcSidIdentifierAuthority
                {
                    IdentifierAuthority = new byte[] { 0, 0, 0, 0, 0, (byte)authority }
                },

                SubAuthority = subAuthorities,
                SubAuthorityCount = (byte)subAuthorities.Count()
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
                return string.Equals(ToString(), sid.ToString(), StringComparison.InvariantCultureIgnoreCase);
            }

            return base.Equals(obj);
        }

        public override int GetHashCode()
        {
            return ToString().GetHashCode();
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
        SE_GROUP_MANDATORY = 0x00000001,
        SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002,
        SE_GROUP_ENABLED = 0x00000004,
        SE_GROUP_OWNER = 0x00000008,
        SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010,
        SE_GROUP_INTEGRITY = 0x00000020,
        SE_GROUP_INTEGRITY_ENABLED = 0x00000040,
        SE_GROUP_RESOURCE = 0x20000000,
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
