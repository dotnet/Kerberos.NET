using System;
using System.Diagnostics;
using Newtonsoft.Json;

namespace Fiddler.Kerberos.NET
{
    public class BinaryConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            Debug.WriteLine(objectType.Name);

            return objectType == typeof(ReadOnlyMemory<byte>) || objectType == typeof(ReadOnlyMemory<byte>?);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (objectType == typeof(ReadOnlyMemory<byte>) && reader.Value != null)
            {
                ReadOnlyMemory<byte> val = Convert.FromBase64String(reader.Value as string);

                return val;
            }

            if (objectType == typeof(ReadOnlyMemory<byte>?) && reader.Value != null)
            {
                ReadOnlyMemory<byte> val = Convert.FromBase64String(reader.Value as string);

                return val;
            }

            return null;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            ReadOnlyMemory<byte> mem = default;

            if (value.GetType() == typeof(ReadOnlyMemory<byte>))
            {
                mem = (ReadOnlyMemory<byte>)value;
            }
            else if (value.GetType() == typeof(ReadOnlyMemory<byte>?))
            {
                var val = (ReadOnlyMemory<byte>?)value;

                if (val != null)
                {
                    mem = val.Value;
                }
            }

            writer.WriteValue(Convert.ToBase64String(mem.ToArray()));
        }
    }
}