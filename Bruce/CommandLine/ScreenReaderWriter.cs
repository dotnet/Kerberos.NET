// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using Humanizer;
using Kerberos.NET.Crypto;
using Kerberos.NET.Logging;
using Kerberos.NET.Reflection;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.CommandLine
{
    internal class ScreenReaderWriter
    {
        private readonly HashSet<object> Seen = new HashSet<object>();

        public ScreenReaderWriter(InputControl io)
        {
            this.IO = io;

            this.Logger = CreateVerboseLogger().CreateLogger(this.GetType().Name);
        }

        protected InputControl IO { get; }

        public int LogOffset { get; set; }

        public ILogger Logger { get; }

        public void ListProperties(object thing, int depth = 2)
        {
            if (thing == null || !Seen.Add(thing))
            {
                return;
            }

            var props = thing.GetType().GetProperties();

            foreach (var prop in props.OrderBy(p => Reflect.IsClass(p.PropertyType) || Reflect.IsEnumerable(p.PropertyType)).ThenBy(p => p.Name))
            {
                if (prop.GetCustomAttributes(typeof(KerberosIgnoreAttribute), true).Any())
                {
                    continue;
                }

                var value = prop.GetValue(thing);

                if (Reflect.IsClass(prop.PropertyType))
                {
                    this.LoggerWriteLine(depth, string.Format("{0} ({{Type}}): {{Value}}", prop.Name.Humanize(LetterCasing.Title)), prop.PropertyType.Name, value == null ? "(null)" : "");

                    if (ReferenceEquals(thing, value))
                    {
                        return;
                    }

                    ListProperties(value, depth + 1);
                }
                else
                {
                    if (Reflect.IsDictionary(prop.PropertyType))
                    {
                        var dict = (IDictionary)value;

                        this.LoggerWriteLine(depth, prop.Name);

                        foreach (object key in dict.Keys)
                        {
                            this.LoggerWriteLine(depth + 1, string.Format("- {0}: {{Value}}", key), dict[key]);
                        }
                    }
                    else if (Reflect.IsEnumerable(prop.PropertyType))
                    {
                        var list = (IEnumerable)value;

                        this.LoggerWriteLine(depth, string.Format("{0} ({{Type}})", prop.Name.Humanize(LetterCasing.Title)), GetListType(prop.PropertyType));

                        foreach (var val in list)
                        {
                            this.LoggerWriteLine(depth + 1, string.Format("- {0}", val.GetType().Name));

                            ListProperties(val, depth + 3);
                        }
                    }
                    else
                    {
                        this.LoggerWriteLine(depth, string.Format("{0}: {{Value}}", prop.Name.Humanize(LetterCasing.Title)), value);
                    }
                }
            }
        }

        public void Write(string message) => this.IO.Writer.Write(message);

        public void WriteAsColor(object value, ConsoleColor color)
        {
            this.IO.SetColor(color);
            this.IO.Writer.Write(value);
            this.IO.ResetColor();
        }

        public ILoggerFactory CreateVerboseLogger(bool labels = false)
        {
            return new KerberosDelegateLogger(
                (level, cateogry, id, scopeState, logState, exception, log)
                    => this.LogImpl(level, exception, logState as IReadOnlyList<KeyValuePair<string, object>>, labels: labels)
            );
        }

        private void LogImpl(
            TraceLevel level,
            Exception exception,
            IReadOnlyList<KeyValuePair<string, object>> logState,
            bool labels
        )
        {
            var indent = this.LogOffset;

            var line = logState.FirstOrDefault(f => f.Key == "{OriginalFormat}").Value?.ToString() ?? "";

            LoggerWriteLine(indent, level, line, logState, exception, labels);
        }

        private void LoggerWriteLine(int indent, string message, params object[] args)
        {
            this.LogOffset = indent;

            this.Logger.LogInformation(message, args);
        }

        private void LoggerWriteLine(int indent, TraceLevel level, string line, IReadOnlyList<KeyValuePair<string, object>> logState = null, Exception exception = null, bool labels = false)
        {
            if (level != TraceLevel.Off && labels)
            {
                var color = level switch
                {
                    TraceLevel.Warning => ConsoleColor.Yellow,
                    TraceLevel.Error => ConsoleColor.Red,
                    _ => ConsoleColor.Green,
                };

                var levelStr = level.ToString();

                this.IO.Writer.Write("[");
                WriteAsColor(levelStr, color);
                this.IO.Writer.Write("] ".PadRight(9 - levelStr.Length));
            }

            var shift = string.Join("", Enumerable.Repeat(' ', indent * 2));

            this.IO.Writer.Write(shift);

            var index = -1;

            for (var i = 0; i < line.Length; i++)
            {
                if (line[i] == '{')
                {
                    index = i;
                    continue;
                }

                if (line[i] == '}')
                {
                    var substr = line[index..i].Replace("{", "").Replace("}", "");

                    var modifierIndex = substr.IndexOf(':');
                    string modifier = null;

                    if (modifierIndex > 0)
                    {
                        modifier = substr[(modifierIndex + 1)..];
                        substr = substr.Substring(0, modifierIndex);
                    }

                    var val = logState?.FirstOrDefault(l => l.Key == substr) ?? default;

                    WriteValue(indent, val, modifier, index);

                    this.IO.ResetColor();
                    index = -1;

                    continue;
                }

                if (index < 0)
                {
                    this.IO.Writer.Write(line[i]);
                }
            }

            this.IO.Writer.WriteLine();

            if (exception != null)
            {
                this.IO.SetColor(ConsoleColor.Red);
                this.IO.Writer.WriteLine(exception.Message);
                this.IO.SetColor(ConsoleColor.DarkYellow);
                this.IO.Writer.WriteLine(exception.StackTrace);
                this.IO.ResetColor();
            }
        }

        private void WriteValue(int indent, KeyValuePair<string, object> val, string modifier, int position)
        {
            if (val.Value is null)
            {
                return;
            }

            var type = val.Value.GetType();

            if (type.IsPrimitive)
            {
                WriteWithModifier(val.Value, modifier, ConsoleColor.DarkYellow);
            }
            else if (type.IsEnum)
            {
                WriteEnum(val);
            }
            else if (Reflect.IsBytes(val.Value, out ReadOnlyMemory<byte> bytes))
            {
                Hex.DumpHex(
                    bytes,
                    (str, index) => this.LoggerWriteLine(index == 0 ? 0 : indent + position / 2, "{Value}", str),
                    bytesPerLine: bytes.Length > 16 ? 16 : 8
                );
            }
            else if (type == typeof(DateTimeOffset))
            {
                var dt = (DateTimeOffset)val.Value;

                if (dt.DateTime > DateTime.UnixEpoch)
                {
                    WriteWithModifier(val.Value, modifier, ConsoleColor.Green);
                }
                else
                {
                    WriteWithModifier("", modifier, ConsoleColor.Green);
                }
            }
            else
            {
                WriteWithModifier(val.Value, modifier, ConsoleColor.DarkCyan);
            }
        }

        private void WriteWithModifier(object val, string modifier, ConsoleColor color)
        {
            if (val is IFormattable formatted && !string.IsNullOrWhiteSpace(modifier))
            {
                var str = formatted.ToString(modifier, null);

                switch (modifier.ToLowerInvariant())
                {
                    case "x":
                    case "x2":
                        str = "0x" + str;
                        break;
                }

                WriteAsColor(str, color);
            }
            else
            {
                WriteAsColor(val, color);
            }
        }

        private void WriteEnum(KeyValuePair<string, object> val)
        {
            var values = GetEnumFriendlyValues(val);

            for (var i = 0; i < values.Count(); i++)
            {
                WriteAsColor(values.ElementAt(i).Trim(), ConsoleColor.Yellow);

                if (i < values.Count() - 1)
                {
                    this.IO.Writer.Write(", ");
                }
            }
        }

        private static IEnumerable<string> GetEnumFriendlyValues(KeyValuePair<string, object> val)
        {
            var enumValues = Enum.GetValues(val.Value.GetType());

            var values = new List<string>();

            var flags = val.Value.GetType().CustomAttributes.Any(a => a.AttributeType == typeof(FlagsAttribute));

            foreach (var enumOption in enumValues)
            {
                var enumValue = (Enum)val.Value;

                if ((flags && enumValue.HasFlag((Enum)enumOption)) || (!flags && enumValue.CompareTo(enumOption) == 0))
                {
                    var enumDisplayName = GetAttribute<DescriptionAttribute>((Enum)enumOption);

                    var enumStr = enumDisplayName != null ? enumDisplayName.Description : enumOption.ToString().Replace("_", "-");

                    values.Add(enumStr);
                }
            }

            return values;
        }

        private static T GetAttribute<T>(Enum value) where T : Attribute
        {
            var type = value.GetType();

            var memberInfo = type.GetMember(value.ToString());

            if (memberInfo.Length <= 0)
            {
                return null;
            }

            var attributes = memberInfo[0].GetCustomAttributes(typeof(T), false);

            return attributes.Length > 0 ? (T)attributes[0] : null;
        }

        private static string GetListType(Type propertyType)
        {
            if (propertyType.IsGenericType)
            {
                return propertyType.GenericTypeArguments.FirstOrDefault()?.Name;
            }
            else if (propertyType.IsArray)
            {
                return propertyType.GetElementType().Name;
            }

            return propertyType.Name;
        }
    }
}
