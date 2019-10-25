using Kerberos.NET.Server;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Type} {FullyQualifiedName}")]
    public partial class KrbPrincipalName
    {
        public string FullyQualifiedName => MakeFullName();

        private string MakeFullName()
        {
            IEnumerable<string> name = Name;

            using (var enumerator = name.GetEnumerator())
            {
                if (!enumerator.MoveNext())
                {
                    return "";
                }

                var sb = new StringBuilder();

                if (enumerator.Current != null)
                {
                    sb.Append(enumerator.Current);
                }

                if (enumerator.MoveNext())
                {
                    sb.Append(NameTypeSeperator[(int)Type]);

                    sb.Append(enumerator.Current);
                }

                while (enumerator.MoveNext())
                {
                    if (enumerator.Current != null)
                    {
                        sb.Append("@");

                        sb.Append(enumerator.Current);
                    }
                }

                return sb.ToString();
            }
        }

        private static readonly string[] NameTypeSeperator = new[] {
            "@", // NT_UNKNOWN = 0,
            "@", // NT_PRINCIPAL = 1,
            "/", // NT_SRV_INST = 2,
            "/", // NT_SRV_HST = 3,
            "/", // NT_SRV_XHST = 4,
            "@", // NT_UID = 5,
            "/", // NT_X500_PRINCIPAL = 6,
            "@", // NT_SMTP_NAME = 7,
            "@", // 8
            "@", // 9
            "@"  // NT_ENTERPRISE = 10
        };

        public bool Matches(object obj)
        {
            var other = obj as KrbPrincipalName;

            if (other == null)
            {
                return false;
            }

            // Any NameType is allowed.  Names collection in two objects must contain at least one common name

            var namesIntersected = other.Name.Intersect(Name);

            if (namesIntersected.Count() == 0)
            {
                return false;
            }

            return true;
        }

        public static KrbPrincipalName FromString(
            string principal,
            PrincipalNameType type = PrincipalNameType.NT_PRINCIPAL,
            string realm = null
        )
        {
            var splitOn = NameTypeSeperator[(int)type][0];

            if (splitOn == '@')
            {
                return SplitAsUpn(principal, realm, type);
            }
            else
            {
                return SplitAsService(principal, realm, type);
            }
        }

        private static KrbPrincipalName SplitAsService(string principal, string realm, PrincipalNameType type)
        {
            var principalSplit = principal.Split('/');

            var name = new List<string>
            {
                principalSplit[0]
            };

            if (principalSplit.Length > 1)
            {
                var nameSplit = SplitAsUpn(principalSplit[1], realm, type);

                name.AddRange(nameSplit.Name);
            }
            else
            {
                if (!string.IsNullOrWhiteSpace(realm))
                {
                    name.Add(realm);
                }
            }

            return new KrbPrincipalName
            {
                Type = type,
                Name = name.ToArray()
            };
        }

        private static KrbPrincipalName SplitAsUpn(string principal, string realm, PrincipalNameType type)
        {
            var nameSplit = principal.Split('@').ToList();

            if (!string.IsNullOrWhiteSpace(realm))
            {
                if (nameSplit.Count == 1)
                {
                    nameSplit.Add(realm);
                }
                else
                {
                    var last = nameSplit.Last();

                    if (!string.Equals(realm, last, StringComparison.OrdinalIgnoreCase))
                    {
                        nameSplit.Add(realm);
                    }
                }
            }

            return new KrbPrincipalName
            {
                Type = type,
                Name = nameSplit.ToArray()
            };
        }

        public static KrbPrincipalName FromPrincipal(
            IKerberosPrincipal principal,
            PrincipalNameType type = PrincipalNameType.NT_PRINCIPAL,
            string realm = null
        )
        {
            return FromString(principal.PrincipalName, type, realm);
        }
    }
}
