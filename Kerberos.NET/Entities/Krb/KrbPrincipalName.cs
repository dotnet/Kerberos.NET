using Kerberos.NET.Server;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Type} {FullyQualifiedName}")]
    public partial class KrbPrincipalName
    {
        private const string KrbtgtService = "krbtgt";
        private const string HostServiceName = "host";

        public static readonly IDictionary<string, string> ServiceAliases = new ConcurrentDictionary<string, string>(new Dictionary<string, string>()
        {
            { "alerter", HostServiceName },
            { "appmgmt", HostServiceName },
            { "cisvc", HostServiceName },
            { "clipsrv", HostServiceName },
            { "browser", HostServiceName },
            { "dhcp", HostServiceName },
            { "dnscache", HostServiceName },
            { "replicator", HostServiceName },
            { "eventlog", HostServiceName },
            { "eventsystem", HostServiceName },
            { "policyagent", HostServiceName },
            { "oakley", HostServiceName },
            { "dmserver", HostServiceName },
            { "dns", HostServiceName },
            { "mcsvc", HostServiceName },
            { "fax", HostServiceName },
            { "msiserver", HostServiceName },
            { "ias", HostServiceName },
            { "messenger", HostServiceName },
            { "netlogon", HostServiceName },
            { "netman", HostServiceName },
            { "netdde", HostServiceName },
            { "netddedsm", HostServiceName },
            { "nmagent", HostServiceName },
            { "plugplay", HostServiceName },
            { "protectedstorage", HostServiceName },
            { "rasman", HostServiceName },
            { "rpclocator", HostServiceName },
            { "rpc", HostServiceName },
            { "rpcss", HostServiceName },
            { "remoteaccess", HostServiceName },
            { "rsvp", HostServiceName },
            { "samss", HostServiceName },
            { "scardsvr", HostServiceName },
            { "scesrv", HostServiceName },
            { "seclogon", HostServiceName },
            { "scm", HostServiceName },
            { "dcom", HostServiceName },
            { "cifs", HostServiceName },
            { "spooler", HostServiceName },
            { "snmp", HostServiceName },
            { "schedule", HostServiceName },
            { "tapisrv", HostServiceName },
            { "trksvr", HostServiceName },
            { "trkwks", HostServiceName },
            { "ups", HostServiceName },
            { "time", HostServiceName },
            { "wins", HostServiceName },
            { "www", HostServiceName },
            { "http", HostServiceName },
            { "w3svc", HostServiceName },
            { "iisadmin", HostServiceName },
            { "msdtc", HostServiceName }
        });

        internal PrincipalName ToKeyPrincipal()
        {
            string realm = "";

            if (Name.Length > 2)
            {
                realm = Name[2];
            }

            return new PrincipalName(Type, realm, Name.Take(2));
        }

        public string FullyQualifiedName => MakeFullName(Name, Type);

        private static string MakeFullName(IEnumerable<string> names, PrincipalNameType type, bool normalizeAlias = false)
        {
            var seperator = NameTypeSeperator[(int)type];

            using (var enumerator = names.GetEnumerator())
            {
                if (!enumerator.MoveNext())
                {
                    return "";
                }

                var sb = new StringBuilder();

                string firstPortion = enumerator.Current;

                if (seperator == "/" && normalizeAlias)
                {
                    if (ServiceAliases.TryGetValue(firstPortion.ToLowerInvariant(), out string alias))
                    {
                        firstPortion = alias;
                    }
                }

                sb.Append(firstPortion);

                if (enumerator.MoveNext())
                {
                    sb.Append(seperator);

                    sb.Append(enumerator.Current);
                }

                while (enumerator.MoveNext())
                {
                    if (enumerator.Current != null)
                    {
                        if (seperator != ",")
                        {
                            sb.Append("@");
                        }
                        else
                        {
                            sb.Append(seperator);
                        }

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
            ",", // NT_X500_PRINCIPAL = 6,
            "@", // NT_SMTP_NAME = 7,
            "@", // 8
            "@", // 9
            "@"  // NT_ENTERPRISE = 10
        };

        public bool Matches(object obj)
        {
            if (obj is null)
            {
                return false;
            }

            if (!(obj is KrbPrincipalName other))
            {
                return false;
            }

            var thisName = MakeFullName(this.Name, this.Type, normalizeAlias: true);
            var otherName = MakeFullName(other.Name, other.Type, normalizeAlias: true);

            return string.Equals(otherName, thisName, StringComparison.InvariantCultureIgnoreCase);
        }

        /// <summary>
        /// Indicates whether the provided <see cref="KrbPrincipalName"/> is
        /// considered a service instead of a user
        /// </summary>
        /// <returns>Returns true if the name is for a service</returns>
        public bool IsServiceName
        {
            get
            {
                switch (Type)
                {
                    case PrincipalNameType.NT_SRV_HST:
                    case PrincipalNameType.NT_SRV_INST:
                    case PrincipalNameType.NT_SRV_XHST:
                        return true;

                    default:
                        return false;
                }
            }
        }

        public static KrbPrincipalName FromString(
            string principal,
            PrincipalNameType? type = null,
            string realm = null
        )
        {
            var actualType = type ?? TryDetectType(principal);

            var splitOn = NameTypeSeperator[(int)actualType][0];

            if (splitOn == '@')
            {
                return SplitAsUpn(principal, realm, actualType);
            }
            else if (splitOn == ',')
            {
                return SplitX500(principal, realm, actualType);
            }
            else
            {
                return SplitAsService(principal, realm, actualType);
            }
        }

        private static PrincipalNameType TryDetectType(string principal)
        {
            if (principal.Contains('/'))
            {
                return PrincipalNameType.NT_SRV_HST;
            }

            if (principal.Contains('@'))
            {
                return PrincipalNameType.NT_PRINCIPAL;
            }

            if (principal.Contains(','))
            {
                return PrincipalNameType.NT_X500_PRINCIPAL;
            }

            return PrincipalNameType.NT_ENTERPRISE;
        }

        private static KrbPrincipalName SplitX500(string principal, string realm, PrincipalNameType type)
        {
            var x500 = new X500DistinguishedName(principal);

            var nameSplit = x500.Name.Split(',').ToList();

            if (!string.IsNullOrWhiteSpace(realm))
            {
                var last = nameSplit.Last();

                if (!last.StartsWith("DC="))
                {
                    var realmSplit = realm.Split('.');

                    foreach (var sub in realmSplit)
                    {
                        nameSplit.Add($"DC={sub}");
                    }
                }
            }

            return new KrbPrincipalName
            {
                Type = type,
                Name = nameSplit.ToArray()
            };
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

            if (!string.IsNullOrWhiteSpace(realm) && nameSplit.Count == 1)
            {
                nameSplit.Add(realm);
            }

            if (type == PrincipalNameType.NT_SRV_INST)
            {
                return new KrbPrincipalName
                {
                    Type = type,
                    Name = nameSplit.ToArray()
                };
            }

            return new KrbPrincipalName
            {
                Type = type,
                Name = new[] { MakeFullName(nameSplit, PrincipalNameType.NT_PRINCIPAL) }
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
        
        public bool IsKrbtgt()
        {
            return string.Equals(Name[0], KrbtgtService, StringComparison.InvariantCultureIgnoreCase);
        }

        public static class WellKnown
        {
            public static KrbPrincipalName Krbtgt() => FromString(KrbtgtService);
        }
    }
}
