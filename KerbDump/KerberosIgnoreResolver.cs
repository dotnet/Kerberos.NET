using Kerberos.NET.Asn1;
using Kerberos.NET.Entities;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace KerbDump
{
    public class KerberosIgnoreResolver : DefaultContractResolver
    {
        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            JsonProperty property = base.CreateProperty(member, memberSerialization);

            var attr = member.GetCustomAttribute<KerberosIgnoreAttribute>();

            if (attr != null)
            {
                property.Ignored = true;
            }

            return property;
        }
    }
}
