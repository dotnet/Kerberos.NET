﻿using System;
using System.Reflection;
using Kerberos.NET;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Fiddler.Kerberos.NET
{
    internal class KerberosIgnoreResolver : DefaultContractResolver
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