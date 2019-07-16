﻿using System;
using System.Diagnostics;
using System.Linq;
using Kerberos.NET.Server;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Type} {FullyQualifiedName}")]
    public partial class KrbPrincipalName
    {
        public string FullyQualifiedName => string.Join("/", this.Name);

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

        public static KrbPrincipalName FromPrincipal(
            IKerberosPrincipal principal,
            PrincipalNameType type = PrincipalNameType.NT_PRINCIPAL,
            string realm = null
        )
        {
            var nameSplit = principal.PrincipalName.Split('@');

            var name = nameSplit[0];

            if (string.IsNullOrWhiteSpace(realm) && nameSplit.Length > 0)
            {
                realm = nameSplit[1];
            }

            return new KrbPrincipalName
            {
                Type = type,
                Name = new[] { name, realm.ToUpperInvariant() }
            };
        }
    }
}
