using Kerberos.NET.Entities;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Kerberos.NET
{
    public class KerberosIdentity : ClaimsIdentity
    {
        public KerberosIdentity(
            IEnumerable<Claim> userClaims,
            string authenticationType,
            string nameType,
            string roleType,
            IEnumerable<Restriction> restrictions,
            ValidationActions validationMode
        ) : base(userClaims, authenticationType, nameType, roleType)
        {
            Restrictions = restrictions.GroupBy(r => r.Type).ToDictionary(r => r.Key, r => r.ToList().AsEnumerable());
            ValidationMode = validationMode;
        }

        public IDictionary<AuthorizationDataType, IEnumerable<Restriction>> Restrictions { get; }

        public ValidationActions ValidationMode { get; }
    }
}
