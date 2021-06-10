// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Type} {FullyQualifiedName}@{Realm}")]
    public class PrincipalName : KrbPrincipalName
    {
        public PrincipalName()
        {
        }

        public PrincipalName(PrincipalNameType Type, string realm, IEnumerable<string> names)
        {
            this.Type = Type;
            this.Realm = realm;
            this.Name = names.ToArray();
        }

        public string Realm { get; set; }

        public static PrincipalName FromKrbPrincipalName(KrbPrincipalName name, string realm = null)
        {
            if (name.Name.Length > 2)
            {
                var possibleRealm = name.Name[2];

                if (string.IsNullOrWhiteSpace(realm))
                {
                    realm = possibleRealm;
                    name.Name = new[] { name.Name[0], name.Name[1] };
                }
            }

            return new PrincipalName(name.Type, realm, name.Name);
        }

        public override bool Equals(object obj)
        {
            return this.Matches(obj);
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(this.Name, this.Type);
        }
    }
}
