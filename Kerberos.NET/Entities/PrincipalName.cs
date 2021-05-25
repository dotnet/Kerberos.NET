// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{NameType} {FullyQualifiedName}@{Realm}")]
    public class PrincipalName
    {
        public PrincipalName()
        {
        }

        public PrincipalName(PrincipalNameType nameType, string realm, IEnumerable<string> names)
        {
            this.NameType = nameType;
            this.Realm = realm;
            this.names = new List<string>(names);
        }

        public string Realm { get; set; }

        private List<string> names;

        public List<string> Names => this.names ?? (this.names = new List<string>());

        public PrincipalNameType NameType { get; set; }

        public string FullyQualifiedName => string.Join("/", this.Names);

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
            if (!(obj is PrincipalName other))
            {
                return false;
            }

            // NT_PRINCIPAL will not match NT_SRV_INST for example

            if (other.NameType != this.NameType)
            {
                return false;
            }

            var namesIntersected = other.Names.Intersect(this.Names);

            // Names list for principal must be exact; additional entries in keytab will fail

            if (namesIntersected.Count() != other.Names.Count || namesIntersected.Count() != this.Names.Count)
            {
                return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(this.Names, this.NameType);
        }
    }
}
