using System;
using System.Collections.Generic;
using Kerberos.NET.Entities.Pac;
using Newtonsoft.Json;

namespace Fiddler.Kerberos.NET.Json
{
    public class RpcConverter : JsonConverter
    {
        private static readonly HashSet<Type> KnownTypes = new HashSet<Type>(new[]
        {
            typeof(RpcString),
            typeof(RpcFileTime),
            typeof(RpcSid),
            typeof(SecurityIdentifier),
        });

        public override bool CanConvert(Type objectType)
        {
            return KnownTypes.Contains(objectType);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (objectType == typeof(RpcString))
            {
                return ((RpcString)existingValue).ToString();
            }
            else if (objectType == typeof(RpcFileTime))
            {
                return (DateTimeOffset)(RpcFileTime)existingValue;
            }
            else if (objectType == typeof(RpcSid))
            {
                return ((RpcSid)existingValue).ToSecurityIdentifier().Value;
            }
            else if (objectType == typeof(SecurityIdentifier))
            {
                return ((SecurityIdentifier)existingValue).Value;
            }
            
            return null;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (value is RpcString str)
            {
                writer.WriteValue(str);
            }
            else if (value is RpcFileTime ft)
            {
                writer.WriteValue((DateTimeOffset)ft);
            }
            else if (value is RpcSid sid)
            {
                writer.WriteValue(sid.ToSecurityIdentifier().Value);
            }
            else if (value is SecurityIdentifier sid2)
            {
                writer.WriteValue(sid2.Value);
            }
        }
    }
}
