using Kerberos.NET.Crypto;
using System;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities.Pac
{
    public class SecurityIdentifier
    {
        private readonly IdentifierAuthority authority;
        private string sddl;

        public SecurityIdentifier(IdentifierAuthority authority, int[] subs, SidAttributes attributes)
        {
            this.authority = authority;
            SubAuthorities = subs;

            Attributes = attributes;

            BinaryForm = ToBinaryForm(authority, subs);
        }

        private static byte[] ToBinaryForm(IdentifierAuthority authority, int[] subs)
        {
            var binaryForm = new Memory<byte>(new byte[(1 + 1 + 6) + 4 * subs.Length]);

            binaryForm.Span[0] = 1; // revision
            binaryForm.Span[1] = (byte)subs.Length;

            Endian.ConvertToBigEndian((int)authority, binaryForm.Slice(4, 4));

            for (var i = 0; i < subs.Length; i++)
            {
                Endian.ConvertToLittleEndian(subs[i], binaryForm.Slice(8 + (4 * i), 4));
            }

            return binaryForm.ToArray();
        }

        public SecurityIdentifier(SecurityIdentifier sid, SidAttributes attributes)
            : this(sid.authority, sid.SubAuthorities, attributes)
        {
        }

        public SecurityIdentifier(ReadOnlySpan<byte> binary, SidAttributes attributes = 0)
        {
            BinaryForm = new ReadOnlyMemory<byte>(binary.ToArray());

            authority = (IdentifierAuthority)binary.Slice(2, 6).AsLong();
            Attributes = attributes;

            SubAuthorities = new int[binary[1]];

            for (var i = 0; i < SubAuthorities.Length; i++)
            {
                SubAuthorities[i] = (int)binary.Slice(8 + (4 * i), 4).AsLong(littleEndian: true);
            }
        }

        [KerberosIgnore]
        public ReadOnlyMemory<byte> BinaryForm { get; }

        public SidAttributes Attributes { get; }

        public string Value { get { return ToString(); } }

        [KerberosIgnore]
        public int[] SubAuthorities { get; }

        public override string ToString()
        {
            if (sddl == null)
            {
                var result = new StringBuilder();

                result.AppendFormat("S-1-{0}", (long)authority);

                for (int i = 0; i < SubAuthorities.Length; i++)
                {
                    result.AppendFormat("-{0}", (uint)(SubAuthorities[i]));
                }

                sddl = result.ToString().ToUpperInvariant();
            }

            return sddl;
        }

        internal SecurityIdentifier AppendTo(SecurityIdentifier sidId)
        {
            var subs = sidId.SubAuthorities.Union(SubAuthorities).ToArray();

            return new SecurityIdentifier(sidId.authority, subs, this.Attributes);
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
    }
}
