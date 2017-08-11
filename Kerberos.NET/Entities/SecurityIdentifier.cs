using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class SecurityIdentifier
    {
        private const byte Revision = 1;

        private readonly IdentifierAuthority authority;
        private readonly int[] subAuthorities;

        private string sddl;

        private static long BytesToLong(byte[] binary, int offset, int max)
        {
            long val = 0;

            for (var i = max; i >= 0; i--)
            {
                val += binary[offset + (max - i)] << (i * 8);
            }

            return val;
        }

        public SecurityIdentifier(IdentifierAuthority authority, int[] subs)
        {
            this.authority = authority;

            subAuthorities = subs;
        }

        public SecurityIdentifier(byte[] binary)
        {
            authority = (IdentifierAuthority)BytesToLong(binary, 2, 5);

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
            var count = this.subAuthorities.Length + sidId.subAuthorities.Length;

            var subs = sidId.subAuthorities.Union(subAuthorities).ToArray();

            return new SecurityIdentifier(sidId.authority, subs);
        }
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
