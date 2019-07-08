using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Kerberos.NET
{
    public class KerberosIdentity : ClaimsIdentity
    {
        internal KerberosIdentity(
            IEnumerable<Claim> userClaims,
            string authenticationType,
            string nameType,
            string roleType,
            IEnumerable<Restriction> restrictions,
            ValidationActions validationMode,
            ReadOnlyMemory<byte>  apRep           
        ) : base(userClaims, authenticationType, nameType, roleType)
        {
            Restrictions = restrictions.GroupBy(r => r.Type).ToDictionary(r => r.Key, r => r.ToList().AsEnumerable());
            ValidationMode = validationMode;
            ApRep = Convert.ToBase64String(apRep.ToArray());
        }

        public IDictionary<AuthorizationDataType, IEnumerable<Restriction>> Restrictions { get; }

        public ValidationActions ValidationMode { get; }

        public string ApRep { get; }
    }
}
