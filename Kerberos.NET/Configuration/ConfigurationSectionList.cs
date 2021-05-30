// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;
using Kerberos.NET.Crypto;
using Kerberos.NET.Reflection;

namespace Kerberos.NET.Configuration
{
    /// <summary>
    /// Provides a list of key-value pairs of &lt;string, object&gt; that represent settings values within a configuration file.
    /// Unlike a hashtable this list can contain multiple keys of the same name;
    /// </summary>
    public class ConfigurationSectionList : List<KeyValuePair<string, object>>
    {
        private const BindingFlags PublicInstancePropertyFlags = BindingFlags.Public | BindingFlags.Instance;

        private static readonly Dictionary<string, string> Aliases = new Dictionary<string, string>()
        {
            { "arcfour_hmac_md5", EncryptionType.RC4_HMAC_NT.ToString() },
            { "arcfour_hmac", EncryptionType.RC4_HMAC_NT.ToString() },
            { "rc4_hmac", EncryptionType.RC4_HMAC_NT.ToString() },
            { "rc4", EncryptionType.RC4_HMAC_NT.ToString() },
            { "aes256_cts", EncryptionType.AES256_CTS_HMAC_SHA1_96.ToString() },
            { "aes128_cts", EncryptionType.AES256_CTS_HMAC_SHA1_96.ToString() },
            { "aes256_sha2", EncryptionType.AES256_CTS_HMAC_SHA384_192.ToString() },
            { "aes128_sha2", EncryptionType.AES128_CTS_HMAC_SHA256_128.ToString() },
            { "aes", string.Join(" ", EncryptionType.AES128_CTS_HMAC_SHA256_128,
                                      EncryptionType.AES128_CTS_HMAC_SHA1_96,
                                      EncryptionType.AES256_CTS_HMAC_SHA384_192,
                                      EncryptionType.AES256_CTS_HMAC_SHA1_96) },
        };

        internal static readonly ConfigurationSectionList Default = Krb5ConfigurationSerializer.Deserialize(string.Empty);

        private readonly List<string> finalizedKeys = new List<string>();

        /// <summary>
        /// Identifies the name of this configuration section.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Converts a <see cref="Krb5Config"/> instance into a <see cref="ConfigurationSectionList" /> for possible future serialization.
        /// </summary>
        /// <param name="config">The configuration instance to load</param>
        /// <returns>Returns a sectioned version of the configuration</returns>
        public static ConfigurationSectionList FromConfigObject(Krb5Config config) => FromConfigObject(config, null);

        /// <summary>
        /// Converts a <see cref="Krb5Config"/> instance into a <see cref="ConfigurationSectionList" /> for possible future serialization.
        /// </summary>
        /// <param name="config">The configuration instance to load</param>
        /// <param name="serializationConfig">Serializer configuration options</param>
        /// <returns>Returns a sectioned version of the configuration</returns>
        public static ConfigurationSectionList FromConfigObject(Krb5Config config, Krb5ConfigurationSerializationConfig serializationConfig)
        {
            if (config is null)
            {
                throw new ArgumentNullException(nameof(config));
            }

            if (serializationConfig == null)
            {
                serializationConfig = new Krb5ConfigurationSerializationConfig();
            }

            var list = new ConfigurationSectionList();

            foreach (var property in config.GetType().GetProperties(PublicInstancePropertyFlags))
            {
                var section = property.GetValue(config);

                list.Add(AddSection(section, property, serializationConfig));
            }

            return list;
        }

        /// <summary>
        /// Gets or sets a value stored in this list. Multiple keys of the same name will be returned as an IEnumerable.
        /// </summary>
        /// <param name="key">The name of the represented value</param>
        /// <returns>Returns a none, one, or more values based on the key.</returns>
        public object this[string key]
        {
            get
            {
                var result = this.Where(e => e.Key == key).Select(e => e.Value);

                var list = new List<object>();

                var endOfList = 0;

                for (; endOfList < result.Count(); endOfList++)
                {
                    var element = result.ElementAt(endOfList);

                    if (element is string str && str.EndsWith("*", StringComparison.OrdinalIgnoreCase))
                    {
                        str = str.Substring(0, str.Length - 1);

                        list.Add(str);

                        break;
                    }
                    else
                    {
                        list.Add(element);
                    }
                }

                result = list;

                var count = result.Count();

                if (count == 0)
                {
                    return null;
                }
                else if (count == 1)
                {
                    return result.First();
                }
                else
                {
                    return result;
                }
            }
            set
            {
                var found = this.FirstOrDefault(e => e.Key == key);

                if (found.Value != null)
                {
                    this.Remove(key);
                }

                this.Add(key, value);
            }
        }

        /// <summary>
        /// Add a value to the collection.
        /// </summary>
        /// <param name="key">The key for the item.</param>
        /// <param name="value">The value of the item.</param>
        public void Add(string key, object value)
        {
            this.Add(new KeyValuePair<string, object>(key, value));
        }

        /// <summary>
        /// Remove any values associated with this key.
        /// </summary>
        /// <param name="key">The key of the items to remove</param>
        public void Remove(string key)
        {
            var values = this.Where(e => e.Key == key).ToList();

            foreach (var val in values)
            {
                this.Remove(val);
            }
        }

        public bool Set(string name, string value, bool append)
        {
            ParseName(name, out string keyName, out string downStreamKey);

            var found = this[keyName];

            if (found is ConfigurationSectionList list && !string.IsNullOrWhiteSpace(downStreamKey))
            {
                var set = list.Set(downStreamKey, value, append);

                if (!set && list.Count == 0)
                {
                    this.Remove(keyName);
                }

                return set;
            }
            else if (found is null && !string.IsNullOrWhiteSpace(downStreamKey))
            {
                found = new ConfigurationSectionList();

                this.Add(keyName, found);

                var set = ((ConfigurationSectionList)found).Set(downStreamKey, value, append);

                if (!set)
                {
                    this.Remove(keyName);
                }

                return set;
            }
            else
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    if (append)
                    {
                        this.Add(keyName, value);
                    }
                    else
                    {
                        this[keyName] = value;
                    }

                    return true;
                }
                else
                {
                    this.Remove(keyName);
                    return false;
                }
            }
        }

        /// <summary>
        /// Get an item by key of a given type.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="key">The key used to find the item</param>
        /// <returns>Returns an item from the list</returns>
        public T Get<T>(string key)
        {
            return (T)this.Get(key, typeof(T));
        }

        /// <summary>
        /// Get an item by key of a given type.
        /// </summary>
        /// <param name="key">The key used to find the item</param>
        /// <param name="type">The type to return</param>
        /// <returns>Returns an item from the list</returns>
        public object Get(string key, Type type)
        {
            return this.Get(key, type, null);
        }

        /// <summary>
        /// Get an item by key of a given type.
        /// </summary>
        /// <param name="key">The key used to find the item</param>
        /// <param name="type">The type to return</param>
        /// <param name="attributes">A list of attributes provided by reflection that describe the form of the type.</param>
        /// <returns>Returns an item from the list</returns>
        public object Get(string key, Type type, IEnumerable<Attribute> attributes)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (this.finalizedKeys.Contains(key))
            {
                return null;
            }

            ParseName(key, out string keyName, out string downStreamKey);

            var found = this[keyName];

            if (found is null)
            {
                found = DefaultValue(attributes, null);
            }

            if (found is ConfigurationSectionList list && !string.IsNullOrWhiteSpace(downStreamKey))
            {
                return list.Get(downStreamKey, type, attributes);
            }

            if (found is string str)
            {
                if (str.EndsWith("*", StringComparison.OrdinalIgnoreCase))
                {
                    this.finalizedKeys.Add(key);

                    found = str.Substring(0, str.Length - 1);
                }
            }

            if (found?.GetType() == type)
            {
                return found;
            }

            return FormatResult(found, type, attributes);
        }

        /// <summary>
        /// Converts the list of values into a structured <see cref="Krb5Config" /> configuration instance.
        /// </summary>
        /// <returns>Returns a configuration instance.</returns>
        public Krb5Config ToConfigObject(Krb5Config config = null)
        {
            if (config is null)
            {
                config = new Krb5Config();
            }

            var properties = config.GetType().GetProperties(PublicInstancePropertyFlags);

            foreach (var property in properties)
            {
                this.SetPropertyValue(config, property);
            }

            return config;
        }

        private static object DefaultValue(IEnumerable<Attribute> attributes, Type expectedType)
        {
            var defaultAttr = attributes?.OfType<DefaultValueAttribute>()?.FirstOrDefault();

            if (defaultAttr == null)
            {
                if (expectedType?.IsValueType ?? false)
                {
                    return Activator.CreateInstance(expectedType);
                }

                return null;
            }

            return defaultAttr.Value;
        }

        private static KeyValuePair<string, object> AddSection(object value, PropertyInfo property, Krb5ConfigurationSerializationConfig serializationConfig)
        {
            var name = GetName(property);

            var config = new ConfigurationSectionList() { Name = name };

            var attributes = property.GetCustomAttributes();

            AddValue(config, value, name, attributes, serializationConfig);

            return new KeyValuePair<string, object>(name, config);
        }

        private static void AddInstance(ConfigurationSectionList value, object config, Type property, Krb5ConfigurationSerializationConfig serializationConfig)
        {
            foreach (var prop in property.GetProperties(PublicInstancePropertyFlags))
            {
                var propertyName = GetName(prop);
                var propertyObject = prop.GetValue(config);

                AddValue(value, propertyObject, propertyName, prop.GetCustomAttributes(), serializationConfig);
            }
        }

        private static void AddValue(ConfigurationSectionList config, object value, string name, IEnumerable<Attribute> attributes, Krb5ConfigurationSerializationConfig serializationConfig)
        {
            if (value == null)
            {
                return;
            }

            var propertyType = value.GetType();

            if (typeof(ICanParseMyself).IsAssignableFrom(propertyType))
            {
                var defaultValue = (ICanParseMyself)Activator.CreateInstance(propertyType);
                defaultValue.Parse(DefaultValue(attributes, null).ToString());

                var serialized = ((ICanParseMyself)value).Serialize();

                if (!AreEqual(serialized, defaultValue.Serialize()))
                {
                    config.Add(new KeyValuePair<string, object>(name, serialized));
                }
            }
            else if (Reflect.IsDictionary(propertyType))
            {
                AddDictionary(config, value, serializationConfig);
            }
            else if (Reflect.IsEnumerable(propertyType))
            {
                AddList(config, name, value, propertyType, attributes, serializationConfig);
            }
            else if (Reflect.IsPrimitive(propertyType))
            {
                AddPrimitive(config, name, value, attributes, serializationConfig);
            }
            else if (propertyType == typeof(ConfigurationSectionList))
            {
                foreach (var val in ((ConfigurationSectionList)value))
                {
                    config.Add(val);
                }
            }
            else
            {
                AddInstance(config, value, propertyType, serializationConfig);
            }
        }

        private static void AddPrimitive(ConfigurationSectionList config, string name, object value, IEnumerable<Attribute> attributes, Krb5ConfigurationSerializationConfig serializerConfig)
        {
            var defaultValue = DefaultValue(attributes, value?.GetType());

            if (AreEqual(defaultValue, value) && !serializerConfig.SerializeDefaultValues)
            {
                return;
            }

            if (value is TimeSpan ts)
            {
                config.Add(new KeyValuePair<string, object>(name, TimeSpanDurationSerializer.ToString(ts)));
            }
            else if (value is DateTimeOffset dt)
            {
                config.Add(new KeyValuePair<string, object>(name, DateTimeAbsoluteSerializer.ToString(dt)));
            }
            else if (typeof(ICanParseMyself).IsAssignableFrom(value.GetType()))
            {
                config.Add(new KeyValuePair<string, object>(name, ((ICanParseMyself)value).Serialize()));
            }
            else if (value is Enum en)
            {
                if (attributes?.OfType<EnumAsIntegerAttribute>()?.Any() ?? false)
                {
                    int val = (int)value;

                    config.Add(new KeyValuePair<string, object>(name, "0x" + val.ToString("X8", CultureInfo.InvariantCulture)));
                }
                else
                {
                    config.Add(new KeyValuePair<string, object>(name, en.ToString().ToLowerInvariant()));
                }
            }
            else if (value is bool b)
            {
                config.Add(new KeyValuePair<string, object>(name, b.ToString().ToLowerInvariant()));
            }
            else
            {
                config.Add(new KeyValuePair<string, object>(name, value));
            }
        }

        private static void AddList(ConfigurationSectionList config, string name, object v, Type propertyType, IEnumerable<Attribute> attributes, Krb5ConfigurationSerializationConfig serializerConfig)
        {
            if (v is null)
            {
                return;
            }

            var genericProp = propertyType.GetGenericArguments()[0];

            if (genericProp.BaseType == typeof(Enum))
            {
                var defaultValue = DefaultValue(attributes, genericProp);

                var value = AddEnum(name, v, attributes);

                if (!AreEqual(defaultValue, value.Value) || serializerConfig.SerializeDefaultValues)
                {
                    config.Add(value);
                }
            }
            else if (typeof(ICanParseMyself).IsAssignableFrom(genericProp))
            {
                var sb = new StringBuilder();

                foreach (var obj in v as IEnumerable)
                {
                    sb.AppendFormat("{0} ", ((ICanParseMyself)obj).Serialize());
                }

                var value = sb.ToString();

                var defaultValue = DefaultValue(attributes, genericProp);

                if (!AreEqual(defaultValue, value))
                {
                    config.Add(new KeyValuePair<string, object>(name, value));
                }
            }
            else
            {
                foreach (var obj in v as IEnumerable)
                {
                    AddValue(config, obj, name, attributes, serializerConfig);
                }
            }
        }

        private static bool AreEqual(object defaultValue, object value)
        {
            if (defaultValue == null && value == null)
            {
                return true;
            }

            if (defaultValue == null && value != null)
            {
                return false;
            }

            if (defaultValue != null && value == null)
            {
                return false;
            }

            if (defaultValue.GetType() == typeof(string) && value.GetType() == typeof(string))
            {
                return string.Equals(((string)defaultValue)?.Trim(), ((string)value)?.Trim(), StringComparison.OrdinalIgnoreCase);
            }

            if (defaultValue.GetType() == typeof(string) && value.GetType() == typeof(TimeSpan))
            {
                return TimeSpanDurationSerializer.Parse((string)defaultValue) == (TimeSpan)value;
            }

            if (defaultValue.GetType() == typeof(string) && value.GetType() == typeof(DateTimeOffset))
            {
                return DateTimeAbsoluteSerializer.Parse((string)defaultValue) == (DateTimeOffset)value;
            }

            return defaultValue.Equals(value);
        }

        private static KeyValuePair<string, object> AddEnum(string name, object list, IEnumerable<Attribute> attributes)
        {
            var sb = new StringBuilder();

            if (list is IEnumerable enums)
            {
                bool requireCsv = attributes?.OfType<CommaSeparatedListAttribute>()?.Any() ?? false;

                foreach (var obj in enums)
                {
                    if (requireCsv)
                    {
                        sb.Append((int)obj);
                        sb.Append(",");
                    }
                    else
                    {
                        sb.Append(obj.ToString().Replace("_", "-"));
                        sb.Append(" ");
                    }
                }
            }

            return new KeyValuePair<string, object>(name, sb.ToString().Trim(' ', ','));
        }

        private static void AddDictionary(ConfigurationSectionList config, object value, Krb5ConfigurationSerializationConfig serializationConfig)
        {
            if (value is IDictionary dict)
            {
                foreach (var key in dict.Keys)
                {
                    var val = dict[key];

                    if (Reflect.IsPrimitive(val.GetType()))
                    {
                        AddValue(config, val, key.ToString(), null, serializationConfig);
                    }
                    else
                    {
                        var dictConfig = new ConfigurationSectionList();

                        config.Add(new KeyValuePair<string, object>(key.ToString(), dictConfig));

                        AddValue(dictConfig, val, key.ToString(), null, serializationConfig);
                    }
                }
            }
        }

        private void SetPropertyValue(Krb5Config config, PropertyInfo property)
        {
            string baseName = GetName(property);

            var propertyType = property.PropertyType;

            property.SetValue(config, this.CreateProperty(propertyType, baseName));
        }

        private static string GetName(PropertyInfo property)
        {
            string baseName = null;

            var dn = property.GetCustomAttribute<DisplayNameAttribute>();

            if (dn != null)
            {
                baseName = dn.DisplayName;
            }

            if (string.IsNullOrWhiteSpace(baseName))
            {
                baseName = property.Name;
            }

            return baseName;
        }

        internal object CreateProperty(Type propertyType, string baseName)
        {
            if (propertyType == typeof(ConfigurationSectionList))
            {
                return this.Get(baseName, propertyType);
            }

            if (Reflect.IsDictionary(propertyType))
            {
                return this.CreatePropertyAsDictionary(propertyType, baseName);
            }

            if (Reflect.IsEnumerable(propertyType))
            {
                return this.CreatePropertyAsList(propertyType, baseName);
            }

            if (Reflect.IsPrimitive(propertyType))
            {
                return this.Get(baseName, propertyType);
            }
            else
            {
                return this.CreateInstance(propertyType, baseName);
            }
        }

        internal object CreateInstance(Type propertyType, string baseName)
        {
            var obj = Activator.CreateInstance(propertyType);

            var configuredProperties = new HashSet<string>();

            var optionalProperty = propertyType.GetProperty(nameof(Krb5ConfigObject.OptionalProperties));

            foreach (var property in propertyType.GetProperties(PublicInstancePropertyFlags))
            {
                if (property.Name == optionalProperty?.Name)
                {
                    continue;
                }

                var name = $"{baseName}.{GetName(property)}";

                object value = null;

                try
                {
                    if (Reflect.IsDictionary(property.PropertyType))
                    {
                        value = this.CreateProperty(property.PropertyType, name);
                    }
                    else
                    {
                        value = this.Get(name, property.PropertyType, property.GetCustomAttributes());
                    }

                    property.SetValue(obj, value);
                }
                catch (Exception ex)
                {
                    throw new ArgumentException($"Property {name} could not be set", ex);
                }

                configuredProperties.Add(name);
            }

            if (optionalProperty != null)
            {
                var allConfiguredValues = (ConfigurationSectionList)this.Get(baseName, typeof(ConfigurationSectionList)) ?? Array.Empty<KeyValuePair<string, object>>().ToList();

                var optional = (ConfigurationSectionList)optionalProperty.GetValue(obj);

                foreach (var leftover in allConfiguredValues)
                {
                    if (!configuredProperties.Contains($"{baseName}.{leftover.Key}"))
                    {
                        optional.Add(leftover.Key, leftover.Value);
                    }
                }
            }

            return obj;
        }

        private object CreatePropertyAsDictionary(Type propertyType, string baseName)
        {
            var dictType = typeof(ConfigurationDictionary<,>);

            var genericArgs = propertyType.GetGenericArguments();

            var concreteType = dictType.MakeGenericType(genericArgs);

            var dict = Activator.CreateInstance(concreteType);

            var add = concreteType.GetMethod("Add");
            var containsKey = concreteType.GetMethod("ContainsKey");

            var values = this.Get<ConfigurationSectionList>(baseName);

            if (values != null)
            {
                foreach (var val in values)
                {
                    if (!(bool)containsKey.Invoke(dict, new[] { val.Key }))
                    {
                        var obj = this.CreateProperty(genericArgs[1], AppendName(baseName, val.Key));

                        if (obj != null)
                        {
                            add.Invoke(dict, new[] { val.Key, obj });
                        }
                    }
                }
            }

            return dict;
        }

        private object CreatePropertyAsList(Type propertyType, string baseName)
        {
            var listType = typeof(List<>);

            var genericParamType = propertyType.GetGenericArguments()[0];

            var concreteType = listType.MakeGenericType(genericParamType);

            var list = Activator.CreateInstance(concreteType);

            var add = concreteType.GetMethod("Add");

            var values = this.Get<ConfigurationSectionList>(baseName);

            foreach (var val in values)
            {
                var obj = this.CreateProperty(genericParamType, AppendName(baseName, val.Key));

                add.Invoke(list, new[] { obj });
            }

            return list;
        }

        private static void ParseName(string key, out string keyName, out string downStreamKey)
        {
            var keys = key.Split(new[] { '.' }, 2, StringSplitOptions.RemoveEmptyEntries);

            if (keys.Length == 0)
            {
                keyName = null;
                downStreamKey = null;
                return;
            }

            keyName = keys[0];
            downStreamKey = keys.Length > 1 ? keys[1] : null;

            if (keyName.StartsWith("\"", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(downStreamKey))
            {
                var nextIndexOfQuote = downStreamKey.IndexOf('"');

                if (nextIndexOfQuote >= 0)
                {
                    keyName = keyName.Substring(1, keyName.Length - 1) + "." + downStreamKey.Substring(0, nextIndexOfQuote);

                    if (nextIndexOfQuote == downStreamKey.Length - 1)
                    {
                        nextIndexOfQuote--;
                    }

                    downStreamKey = downStreamKey.Substring(nextIndexOfQuote + 2);
                }
            }
        }

        private static object FormatResult(object found, Type type, IEnumerable<Attribute> attributes)
        {
            if (!(found is string) &&
                type != typeof(string) &&
                type != typeof(ConfigurationSectionList) &&
                typeof(IEnumerable).IsAssignableFrom(type))
            {
                return ParseAsList((IEnumerable)found, type);
            }

            if (found == null)
            {
                return null;
            }

            var stringValue = found.ToString();

            if (type.IsGenericType &&
               (type.GetGenericTypeDefinition() == typeof(ICollection<>) ||
                type.GetGenericTypeDefinition() == typeof(IEnumerable<>)))
            {
                return ParseAsList(stringValue, type);
            }
            else if (type.BaseType == typeof(Enum))
            {
                if (attributes?.OfType<EnumAsIntegerAttribute>()?.Any() ?? false)
                {
                    var value = Convert.ToInt32(stringValue, 16);

                    return Enum.ToObject(type, value);
                }

                return Enum.Parse(type, stringValue, true);
            }

            return Parse(stringValue, type);
        }

        private static object ParseAsList(string stringValue, Type type)
        {
            // treat as list of things no matter what

            var stringValues = stringValue.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);

            return ParseAsList(stringValues, type);
        }

        private static object ParseAsList(IEnumerable stringValues, Type type)
        {
            var listType = typeof(List<>);

            var genericParamType = type.GetGenericArguments()[0];

            var concreteType = listType.MakeGenericType(genericParamType);

            var list = Activator.CreateInstance(concreteType);

            var add = concreteType.GetMethod("Add");
            var addRange = concreteType.GetMethod("AddRange");

            if (stringValues != null)
            {
                foreach (var val in stringValues)
                {
                    var parsed = Parse(val.ToString(), genericParamType);

                    if (parsed == null)
                    {
                        continue;
                    }

                    if ((parsed is IEnumerable || parsed is ICollection) && !(parsed is string))
                    {
                        addRange.Invoke(list, new[] { parsed });
                    }
                    else
                    {
                        add.Invoke(list, new[] { parsed });
                    }
                }
            }

            return list;
        }

        private static object Parse(string stringValue, Type type)
        {
            if (string.IsNullOrWhiteSpace(stringValue))
            {
                return null;
            }

            if (type == typeof(TimeSpan))
            {
                return TimeSpanDurationSerializer.Parse(stringValue);
            }

            if (type == typeof(DateTimeOffset))
            {
                return DateTimeAbsoluteSerializer.Parse(stringValue);
            }

            if (type.BaseType == typeof(Enum))
            {
                return ParseEnum(stringValue, type);
            }

            if (type == typeof(bool))
            {
                return ParseBool(stringValue);
            }

            if (typeof(ICanParseMyself).IsAssignableFrom(type))
            {
                var instance = (ICanParseMyself)Activator.CreateInstance(type);

                instance.Parse(stringValue);

                return instance;
            }

            return Convert.ChangeType(stringValue, type, CultureInfo.InvariantCulture);
        }

        private static object ParseBool(string stringValue)
        {
            if (string.Equals("yes", stringValue, StringComparison.InvariantCultureIgnoreCase))
            {
                return true;
            }
            else if (string.Equals("no", stringValue, StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            return bool.Parse(stringValue);
        }

        public static object ParseEnum(string stringValue, Type type)
        {
            var val = stringValue.Replace("-", "_");

            if (Aliases.TryGetValue(val, out string aliased))
            {
                val = aliased;
            }

            var split = val.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);

            if (split.Length > 1)
            {
                var concreteType = typeof(List<>).MakeGenericType(type);

                return ParseAsList(split, concreteType);
            }
            else
            {
                try
                {
                    return Enum.Parse(type, val, true);
                }
                catch (ArgumentException)
                {
                    return null;
                }
            }
        }

        private static string AppendName(string basePath, string name)
        {
            if (name.Contains('.'))
            {
                return $"{basePath}.\"{name}\"";
            }

            return $"{basePath}.{name}";
        }
    }
}
