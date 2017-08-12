using System;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class SecurityIdentifier
    {
        private readonly IdentifierAuthority authority;
        private readonly int[] subAuthorities;

        private string sddl;
        
        public SecurityIdentifier(IdentifierAuthority authority, int[] subs, SidAttributes attributes)
        {
            this.authority = authority;
            subAuthorities = subs;

            Attributes = attributes;
        }

        public SecurityIdentifier(SecurityIdentifier sid, SidAttributes attributes)
            : this(sid.authority, sid.subAuthorities, attributes)
        {
        }

        public SecurityIdentifier(byte[] binary, SidAttributes attributes = 0)
        {
            authority = (IdentifierAuthority)BytesToLong(binary, 2, 5);
            Attributes = attributes;

            var subs = new int[binary[1]];

            for (var i = 0; i < binary[1]; i++)
            {
                subs[i] =
                    (int)(
                        (((uint)binary[8 + 4 * i + 0]) << 0) +
                        (((uint)binary[8 + 4 * i + 1]) << 8) +
                        (((uint)binary[8 + 4 * i + 2]) << 16) +
                        (((uint)binary[8 + 4 * i + 3]) << 24)
                );
            }

            subAuthorities = new int[subs.Length];

            subs.CopyTo(subAuthorities, 0);
        }

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
                    result.AppendFormat("-{0}", (uint)(subAuthorities[i]));
                }

                sddl = result.ToString().ToUpperInvariant();
            }

            return sddl;
        }

        internal SecurityIdentifier AppendTo(SecurityIdentifier sidId)
        {
            var subs = sidId.subAuthorities.Union(subAuthorities).ToArray();

            return new SecurityIdentifier(sidId.authority, subs, this.Attributes);
        }
        
        private static long BytesToLong(byte[] binary, int offset, int max)
        {
            long val = 0;

            for (var i = max; i >= 0; i--)
            {
                val += binary[offset + (max - i)] << (i * 8);
            }

            return val;
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

    public enum IdentifierAuthority : long
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
    }
}
