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
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Logging;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.CommandLine
{
    public abstract class BaseCommand : ICommand
    {
        private static readonly IEnumerable<string> ParameterDesignators = new[] { "/", "--", "-" };

        protected BaseCommand(CommandLineParameters parameters)
        {
            this.Parameters = parameters;

            this.ParseParameters();

            this.Logger = CreateVerboseLogger().CreateLogger(this.GetType().Name);
        }

        private InputControl IO => ((ICommand)this).IO;

        InputControl ICommand.IO { get; set; }

        public CommandLineParameters Parameters { get; }

        [CommandLineParameter("h|help|?", Description = "Help")]
        public bool Help { get; protected set; }

        protected ILogger Logger { get; }

        protected virtual void WriteLine() => this.WriteLine("");

        protected virtual void WriteHeader(string message)
        {
            this.IO.SetColor(ConsoleColor.Yellow);
            WriteLine("  " + message);
            this.IO.ResetColor();
        }

        protected virtual void WriteLineRaw(string message)
        {
            this.IO.SetColor(ConsoleColor.White);
            this.IO.Writer.WriteLine(message);
            this.IO.ResetColor();
        }

        protected virtual void WriteLine(string message, params object[] args)
        {
            this.Logger.LogInformation(message, args);
        }

        protected virtual void WriteLineWarning(string message, params object[] args)
        {
            CreateVerboseLogger(labels: true).CreateLogger(this.GetType().Name).LogWarning(message, args);
        }

        protected virtual void WriteLineError(string message, params object[] args)
        {
            CreateVerboseLogger(labels: true).CreateLogger(this.GetType().Name).LogError(message, args);
        }

        protected virtual KerberosClient CreateClient(string configValue = null, bool verbose = false)
        {
            Krb5Config config;

            if (!string.IsNullOrWhiteSpace(configValue))
            {
                config = Krb5Config.Parse(configValue);
            }
            else
            {
                config = Krb5Config.CurrentUser();
            }

            ILoggerFactory logger = null;

            if (verbose)
            {
                logger = this.CreateVerboseLogger(labels: true);
            }

            return new KerberosClient(config, logger) { CacheInMemory = false };
        }

        protected ILoggerFactory CreateVerboseLogger(bool labels = false)
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
            var line = logState.FirstOrDefault(f => f.Key == "{OriginalFormat}").Value?.ToString() ?? "";

            WriteLine(level, line, logState, exception, labels);

        }

        protected void WriteLine(TraceLevel level, string line, IReadOnlyList<KeyValuePair<string, object>> logState = null, Exception exception = null, bool labels = false)
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
                this.IO.SetColor(color);
                this.IO.Writer.Write(levelStr);
                this.IO.ResetColor();
                this.IO.Writer.Write("] ".PadRight(9 - levelStr.Length));
            }

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
                    var substr = line.Substring(index, i - index).Replace("{", "").Replace("}", "");

                    var val = logState?.FirstOrDefault(l => l.Key == substr) ?? default;

                    WriteValue(val);

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

        private void WriteValue(KeyValuePair<string, object> val)
        {
            if (val.Value is null)
            {
                return;
            }

            var type = val.Value.GetType();

            if (type.IsPrimitive)
            {
                this.IO.SetColor(ConsoleColor.DarkYellow);

                this.IO.Writer.Write(val.Value);
            }
            else if (type.IsEnum)
            {
                WriteEnum(val);
            }
            else if (type == typeof(DateTimeOffset))
            {
                this.IO.SetColor(ConsoleColor.Green);

                var dt = (DateTimeOffset)val.Value;

                if (dt.DateTime > DateTime.UnixEpoch)
                {
                    this.IO.Writer.Write(val.Value);
                }
                else
                {
                    this.IO.Writer.Write("");
                }
            }
            else
            {
                this.IO.SetColor(ConsoleColor.DarkCyan);

                this.IO.Writer.Write(val.Value);
            }
        }

        private void WriteEnum(KeyValuePair<string, object> val)
        {
            var values = GetEnumFriendlyValues(val);

            for (var i = 0; i < values.Count(); i++)
            {
                this.IO.SetColor(ConsoleColor.Yellow);
                this.IO.Writer.Write(values.ElementAt(i).Trim());
                this.IO.ResetColor();

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

                    var enumStr = enumDisplayName != null ? enumDisplayName.Description : enumOption.ToString();

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

        protected virtual T CreateCommand<T>()
            where T : ICommand
        {
            var command = (ICommand)Activator.CreateInstance(typeof(T), this.Parameters);

            command.IO = this.IO;

            return (T)command;
        }

        public virtual Task<bool> Execute()
        {
            if (this.Help)
            {
                this.DisplayHelp();

                return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }

        public virtual void DisplayHelp()
        {
            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendFormat("{0}: {1} ", SR.Resource("CommandLine_Usage"), this.Parameters.Command);

            var typeProperties = this.GetType().GetProperties();

            var props = new List<(PropertyInfo, CommandLineParameterAttribute)>();

            foreach (var prop in typeProperties)
            {
                var attr = prop.GetCustomAttribute<CommandLineParameterAttribute>();

                if (attr == null)
                {
                    continue;
                }

                props.Add((prop, attr));

                if (string.IsNullOrWhiteSpace(attr.Name))
                {
                    continue;
                }

                if (attr.FormalParameter)
                {
                    sb.AppendFormat("{0} ", attr.Name);

                    sb.AppendFormat("[{0}] ", WriteProperty(prop, attr));
                }
                else
                {
                    sb.Append(WriteProperty(prop, attr));
                    sb.Append(" ");
                }
            }

            this.WriteHeader(sb.ToString());

            var max = props.Select(p => p.Item2.Name).Max(p =>
                p.Length + 7 +
               (p.Count(c => c == '|') * 9)
            ) + 5;

            this.IO.Writer.WriteLine();
            this.IO.Writer.WriteLine();

            foreach (var prop in props)
            {
                WritePropertyDescription(prop.Item1.PropertyType, prop.Item2, this.GetType().Name, padding: max);
                this.IO.Writer.WriteLine();
            }

            this.IO.Writer.WriteLine();
        }

        private string WriteProperty(PropertyInfo prop, CommandLineParameterAttribute attr)
        {
            StringBuilder sb = new StringBuilder();

            var names = attr.Name.Split('|');

            var hasValue = prop.PropertyType != typeof(bool) &&
                           prop.PropertyType != typeof(bool?);

            for (var i = 0; i < names.Length; i++)
            {
                var name = names[i];

                if (!attr.Required)
                {
                    sb.AppendFormat("[");
                }

                string value;

                if (name.Length > 1)
                {
                    if (hasValue)
                    {
                        value = $"--{name}=value";
                    }
                    else
                    {
                        value = $"--{name}";
                    }
                }
                else
                {
                    if (hasValue)
                    {
                        value = $"-{name} value";
                    }
                    else
                    {
                        value = $"-{name}";
                    }
                }

                sb.Append(value);

                if (!attr.Required)
                {
                    sb.AppendFormat("]");
                }

                if (i < names.Length - 1)
                {
                    sb.AppendFormat(" ");
                }
            }

            return sb.ToString();
        }

        private void WritePropertyDescription(Type propertyType, CommandLineParameterAttribute attr, string commandPrefix, int padding)
        {
            var names = attr.Name.Split('|');

            var hasValue = propertyType != typeof(bool) &&
                           propertyType != typeof(bool?);

            bool last = false;

            var sbName = new StringBuilder();

            for (var i = 0; i < names.Length; i++)
            {
                var name = names[i];

                if (i == names.Length - 1)
                {
                    last = true;
                }

                if (name.Length > 1)
                {
                    if (hasValue)
                    {
                        sbName.Append($"--{name}=value");
                    }
                    else
                    {
                        sbName.Append($"--{name}");
                    }
                }
                else
                {
                    if (hasValue)
                    {
                        sbName.Append($"-{name} value");
                    }
                    else
                    {
                        sbName.Append($"-{name}");
                    }
                }

                if (!last && names.Length > 1)
                {
                    sbName.Append(", ");
                }
            }

            var sb = new StringBuilder();

            var sbNameVal = sbName.ToString();

            sb.Append(sbNameVal.PadLeft(sbNameVal.Length + 3).PadRight(padding));

            var descName = "CommandLine_" + commandPrefix + "_" + attr.Description;

            var desc = SR.Resource(descName);

            if (string.Equals(descName, desc, StringComparison.InvariantCultureIgnoreCase))
            {
                sb.Append(attr.Description);
            }
            else
            {
                sb.Append(desc);
            }

            this.IO.Writer.Write(sb.ToString());
        }

        private void ParseParameters()
        {
            if (this.Parameters?.Parameters == null)
            {
                return;
            }

            var typeProperties = this.GetType().GetProperties();

            var parameters = this.Parameters.Parameters.ToArray();

            PropertyInfo formalParameter = null;

            foreach (var prop in typeProperties)
            {
                var attr = prop.GetCustomAttribute<CommandLineParameterAttribute>();

                if (attr == null)
                {
                    continue;
                }

                if (attr.FormalParameter)
                {
                    formalParameter = prop;
                    continue;
                }

                SetPropertyValue(prop, attr, ref parameters);
            }

            parameters = parameters.Where(p => !string.IsNullOrWhiteSpace(p)).ToArray();

            if (parameters.Any() && formalParameter != null)
            {
                SetValue(this, formalParameter, null, parameters.ElementAt(parameters.Count() - 1));
            }
        }

        private void SetPropertyValue(PropertyInfo prop, CommandLineParameterAttribute attr, ref string[] parameters)
        {
            for (var i = 0; i < parameters.Length; i++)
            {
                string param = parameters[i];

                if (string.IsNullOrWhiteSpace(param))
                {
                    continue;
                }

                if (IsParameter(param, out string designator))
                {
                    param = param.Substring(designator.Length);
                }

                string nextValue = "";

                var indexOfEquals = param.IndexOf('=');

                if (indexOfEquals > 0)
                {
                    nextValue = param.Substring(indexOfEquals + 1);
                    param = param.Substring(0, indexOfEquals);
                }

                var names = attr.Name.Split('|');

                bool matches = false;

                foreach (var name in names)
                {
                    if (string.Equals(name, param, attr.EnforceCasing ? StringComparison.Ordinal : StringComparison.InvariantCultureIgnoreCase))
                    {
                        matches = true;
                        break;
                    }
                }

                if (matches)
                {
                    parameters[i] = null;

                    if (i < parameters.Length - 1)
                    {
                        i++;

                        if (string.IsNullOrWhiteSpace(nextValue))
                        {
                            nextValue = parameters[i];
                        }
                    }

                    if (SetValue(this, prop, param, nextValue))
                    {
                        parameters[i] = null;
                    }
                }
            }
        }

        private static bool SetValue(object instance, PropertyInfo prop, string param, string nextValue)
        {
            var type = prop.PropertyType;
            var existingValue = prop.GetValue(instance);

            var value = ParseValue(type, existingValue, param, nextValue, out bool usedValue);

            prop.SetValue(instance, value);

            return usedValue;
        }

        private static object ParseValue(Type type, object existingValue, string param, string nextValue, out bool usedValue)
        {
            usedValue = true;

            object value;

            if (type.IsGenericType &&
               (type.GetGenericTypeDefinition() == typeof(ICollection<>) ||
                type.GetGenericTypeDefinition() == typeof(IEnumerable<>)))
            {
                value = SetOrAddCollectionValue(type, existingValue, nextValue);
            }
            else if (type == typeof(bool) || type == typeof(bool?))
            {
                if (!bool.TryParse(nextValue, out bool result))
                {
                    result = true;
                    usedValue = false;
                }

                value = result;
            }
            else if (type == typeof(TimeSpan) || type == typeof(TimeSpan?))
            {
                var ts = TimeSpanDurationSerializer.Parse(nextValue);
                value = ts;
            }
            else if (type.BaseType == typeof(Enum))
            {
                if (string.IsNullOrWhiteSpace(nextValue))
                {
                    return null;
                }

                value = ConfigurationSectionList.ParseEnum(nextValue, type);
            }
            else
            {
                value = nextValue;
            }

            return value;
        }

        private static object SetOrAddCollectionValue(Type type, object list, string nextValue)
        {
            var listType = typeof(List<>);

            var genericParamType = type.GetGenericArguments()[0];

            var concreteType = listType.MakeGenericType(genericParamType);

            if (list == null)
            {
                list = Activator.CreateInstance(concreteType);
            }

            var add = concreteType.GetMethod("Add");
            var addRange = concreteType.GetMethod("AddRange");

            var value = ParseValue(genericParamType, null, null, nextValue, out _);

            if (value is IEnumerable || value is ICollection)
            {
                addRange.Invoke(list, new[] { value });
            }
            else
            {
                add.Invoke(list, new[] { value });
            }

            return list;
        }

        protected static bool IsParameter(string parameter, out string designator)
        {
            designator = null;

            foreach (var des in ParameterDesignators)
            {
                if (parameter.StartsWith(des))
                {
                    designator = des;
                    return true;
                }
            }

            return false;
        }
    }
}
