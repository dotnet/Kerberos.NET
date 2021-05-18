// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Kerberos.NET.Configuration
{
    public static class Krb5ConfigurationSerializer
    {
        private const char CommentHash = '#';
        private const char CommentSemi = ';';
        private const char SectionOpen = '[';
        private const char SectionClose = ']';
        private const char GroupOpen = '{';
        private const char GroupClose = '}';
        private const char EndOfValue = '*';

        private static readonly char[] Equal = new char[] { '=' };

        /// <summary>
        /// Deserialize a configuration value into a <see cref="ConfigurationSectionList" /> for querying values by key.
        /// </summary>
        /// <param name="configuration">The configuration to parse.</param>
        /// <returns>Returns a configuration list of key-value pairs.</returns>
        public static ConfigurationSectionList Deserialize(string configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var reader = new StringReader(configuration);

            var config = new ConfigurationSectionList();

            while (TryReadLine(reader, out string currentLine))
            {
                if (CanSkip(currentLine))
                {
                    continue;
                }

                while (IsSectionLine(currentLine))
                {
                    var section = new ConfigurationSectionList();

                    currentLine = ReadSection(currentLine, reader, section);

                    config.Add(new KeyValuePair<string, object>(section.Name, section));
                }
            }

            return config;
        }

        /// <summary>
        /// Serialize a configuration object instance into a configuration file.
        /// </summary>
        /// <param name="configuration">The configuration to serialize.</param>
        /// <param name="serializationConfig">Optional configuration that describes the format requested.</param>
        /// <returns>Returns the configuration in string form.</returns>
        public static string Serialize(Krb5Config configuration, Krb5ConfigurationSerializationConfig serializationConfig = null)
        {
            return Serialize(ConfigurationSectionList.FromConfigObject(configuration, serializationConfig), serializationConfig);
        }

        /// <summary>
        /// Serialize a configuration list into a configuration file.
        /// </summary>
        /// <param name="configuration">The configuration to serialize.</param>
        /// <param name="serializerConfig">Optional configuration that describes the format requested.</param>
        /// <returns>Returns the configuration in string form.</returns>
        public static string Serialize(ConfigurationSectionList configuration, Krb5ConfigurationSerializationConfig serializerConfig = null)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            if (serializerConfig is null)
            {
                serializerConfig = new Krb5ConfigurationSerializationConfig();
            }

            var sb = new StringBuilder();

            foreach (var config in configuration)
            {
                if (config.Value is ConfigurationSectionList section)
                {
                    SerializeSection(sb, section, serializerConfig);
                }
            }

            return sb.ToString();
        }

        private static void SerializeSection(StringBuilder sb, ConfigurationSectionList section, Krb5ConfigurationSerializationConfig serializerConfig)
        {
            sb.AppendFormat(CultureInfo.InvariantCulture, "[{0}]", section.Name);
            sb.AppendLine();

            foreach (var config in section)
            {
                var val = config.Value;

                SerializeValue(sb, config.Key, val, serializerConfig);
            }

            sb.AppendLine();
        }

        private static void SerializeValue(StringBuilder sb, string key, object val, Krb5ConfigurationSerializationConfig serializerConfig)
        {
            if (val is ConfigurationSectionList multiVal)
            {
                SerializeValues(sb, key, multiVal, serializerConfig);
            }
            else
            {
                Indent(sb, serializerConfig);
                sb.AppendFormat(CultureInfo.InvariantCulture, "{0} = {1}", key, val);
                sb.AppendLine();
            }
        }

        private static void Indent(StringBuilder sb, Krb5ConfigurationSerializationConfig serializerConfig)
        {
            for (var i = 0; i < serializerConfig.CurrentIndent * serializerConfig.IndentWidth; i++)
            {
                sb.Append(" ");
            }
        }

        private static void SerializeValues(StringBuilder sb, string key, ConfigurationSectionList multiVal, Krb5ConfigurationSerializationConfig serializerConfig)
        {
            Indent(sb, serializerConfig);
            sb.AppendFormat(CultureInfo.InvariantCulture, "{0} = {{", key);
            sb.AppendLine();

            serializerConfig.CurrentIndent++;

            foreach (var multi in multiVal)
            {
                var val = multi.Value;

                SerializeValue(sb, multi.Key, val, serializerConfig);
            }

            serializerConfig.CurrentIndent--;

            Indent(sb, serializerConfig);
            sb.AppendLine("}");
        }

        private static bool IsSectionLine(string currentLine)
        {
            if (string.IsNullOrWhiteSpace(currentLine))
            {
                return false;
            }

            return currentLine[0] == SectionOpen && currentLine[currentLine.Length - 1] == SectionClose;
        }

        private static string ReadSection(string currentLine, StringReader reader, ConfigurationSectionList section)
        {
            section.Name = currentLine.Substring(1, currentLine.Length - 2);

            while (TryReadLine(reader, out currentLine))
            {
                if (CanSkip(currentLine))
                {
                    continue;
                }

                if (currentLine[0] == SectionOpen)
                {
                    break;
                }

                ReadValue(currentLine, reader, section);
            }

            return currentLine;
        }

        private static void ReadValue(string currentLine, StringReader reader, ConfigurationSectionList section)
        {
            if (currentLine.IndexOf(GroupOpen) >= 0)
            {
                ReadValues(currentLine, reader, section);
            }
            else
            {
                var split = currentLine.Split(Equal, 2);

                if (split.Length == 2)
                {
                    section.Add(new KeyValuePair<string, object>(split[0].Trim(), split[1].Trim()));
                }

                if (currentLine[currentLine.Length - 1] == EndOfValue)
                {
                    // skip future
                }
            }
        }

        private static void ReadValues(string currentLine, StringReader reader, ConfigurationSectionList section)
        {
            var split = currentLine.Split(Equal, 2);

            if (split.Length != 2)
            {
                return;
            }

            var config = new ConfigurationSectionList();

            while (TryReadLine(reader, out currentLine))
            {
                if (CanSkip(currentLine))
                {
                    continue;
                }

                if (currentLine[0] == GroupClose)
                {
                    break;
                }

                ReadValue(currentLine, reader, config);
            }

            section.Add(new KeyValuePair<string, object>(split[0].Trim(), config));
        }

        private static bool TryReadLine(StringReader reader, out string currentLine)
        {
            currentLine = reader.ReadLine();

            if (currentLine == null)
            {
                return false;
            }

            for (var i = 0; i < currentLine.Length; i++)
            {
                if (IsComment(currentLine[i]))
                {
                    currentLine = currentLine.Substring(0, i);
                    break;
                }
            }

            currentLine = currentLine.Trim().Trim('\uFEFF', '\u200B');

            return true;
        }

        private static bool CanSkip(string trimmed)
        {
            if (trimmed.Length == 0)
            {
                return true;
            }

            return IsComment(trimmed[0]);
        }

        private static bool IsComment(char ch)
        {
            switch (ch)
            {
                case CommentSemi:
                case CommentHash:
                    return true;
            }

            return false;
        }
    }
}
