// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.CommandLine
{
    public abstract class BaseCommand : ICommand
    {
        private ScreenReaderWriter io;

        protected BaseCommand(CommandLineParameters parameters)
        {
            this.Parameters = parameters;

            this.ParseParameters();

            this.CalculateUserAndRealm();
        }

        private protected ScreenReaderWriter IO => this.io ??= new ScreenReaderWriter(((ICommand)this).IO);

        InputControl ICommand.IO { get; set; }

        public CommandLineParameters Parameters { get; }

        public string DefaultRealm => Environment.GetEnvironmentVariable("USERDNSDOMAIN");

        public virtual string Realm { get; set; }

        public virtual string UserPrincipalName { get; set; }

        public virtual string ConfigurationPath { get; set; }

        public virtual bool Verbose { get; protected set; }

        [CommandLineParameter("h|help|?", Description = "Help")]
        public bool Help { get; protected set; }

        protected virtual KerberosClient CreateClient(string configValue = null, bool verbose = false)
        {
            Krb5Config config;

            if (!string.IsNullOrWhiteSpace(configValue))
            {
                config = Krb5Config.Parse(configValue);
            }
            else
            {
                config = Krb5Config.CurrentUser(this.ConfigurationPath);
            }

            ILoggerFactory logger = null;

            if (verbose)
            {
                logger = this.IO.CreateVerboseLogger(labels: true);
            }

            return new KerberosClient(config, logger) { CacheInMemory = false };
        }

        protected virtual T CreateCommand<T>()
            where T : ICommand
        {
            var command = (ICommand)Activator.CreateInstance(typeof(T), this.Parameters);

            command.IO = ((ICommand)this).IO;

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

            this.WriteLine();
            this.WriteHeader(sb.ToString());

            var max = props.Select(p => p.Item2.Name).Max(p =>
                p.Length + 7 +
               (p.Count(c => c == '|') * 9)
            ) + 5;

            this.WriteLine();

            foreach (var prop in props)
            {
                WritePropertyDescription(prop.Item1.PropertyType, prop.Item2, this.GetType().Name, padding: max);
                this.WriteLine();
            }

            this.WriteLine();
        }

        protected virtual void WriteLine() => this.WriteLine(0, "");

        protected virtual void WriteHeader(string message)
        {
            this.IO.WriteAsColor("   " + message, ConsoleColor.Yellow);
            WriteLine();
        }

        protected virtual void WriteLineRaw(string message)
        {
            this.IO.WriteAsColor(message, ConsoleColor.White);
        }

        protected virtual void WriteLine(string message, params object[] args)
        {
            WriteLine(0, message, args);
        }

        protected virtual void WriteLine(int indent, string message, params object[] args)
        {
            this.IO.LogOffset = indent;

            this.IO.Logger.LogInformation(string.Format("{0}", message), args);
        }

        protected virtual void WriteLineWarning(string message, params object[] args)
        {
            this.IO.Logger.LogWarning(message, args);
        }

        protected virtual void WriteLineError(string message, params object[] args)
        {
            this.IO.Logger.LogError(message, args);
        }

        protected void WriteProperties(IEnumerable<(string, string)> props)
        {
            var max = props.Max(p => p.Item1.Length) + 3;

            foreach (var prop in props)
            {
                this.WriteProperty(prop.Item1, prop.Item2, max);
            }
        }

        protected void WriteProperty(string key, string value, int padding)
        {
            this.WriteLine(
                string.Format(
                    "{0}: {{Value}}",
                    key.PadLeft(padding).PadRight(padding)
                ),
                value
            );
        }

        private string WriteProperty(PropertyInfo prop, CommandLineParameterAttribute attr)
        {
            var sb = new StringBuilder();

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

            this.IO.Write(sb.ToString());
        }

        private void CalculateUserAndRealm()
        {
            var client = CreateClient();

            if (string.IsNullOrWhiteSpace(this.Realm))
            {
                this.Realm = client.DefaultDomain;

                if (string.IsNullOrWhiteSpace(this.UserPrincipalName))
                {
                    this.UserPrincipalName = client.UserPrincipalName;
                }
            }

            if (string.IsNullOrWhiteSpace(this.Realm))
            {
                this.Realm = this.DefaultRealm;
            }

            if (string.IsNullOrWhiteSpace(this.UserPrincipalName))
            {
                this.UserPrincipalName = Environment.UserName;
            }

            if (!this.UserPrincipalName.Contains("@") && !string.IsNullOrWhiteSpace(this.Realm))
            {
                this.UserPrincipalName = $"{this.UserPrincipalName}@{this.Realm}";
            }
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

                if (CommandLineParameters.IsParameter(param, out string designator))
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
            else if (type == typeof(DateTimeOffset) || type == typeof(DateTimeOffset?))
            {
                var dt = DateTimeAbsoluteSerializer.Parse(nextValue);
                value = dt;
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

        protected string ReadMasked()
        {
            var masked = "";

            try
            {
                this.IO.HookCtrlC(true);

                do
                {
                    ConsoleKeyInfo key = this.IO.ReadKey();

                    if (key.Modifiers.HasFlag(ConsoleModifiers.Control) && key.Key == ConsoleKey.C)
                    {
                        this.IO.Writer.WriteLine();
                        return null;
                    }
                    else if (key.Key != ConsoleKey.Backspace &&
                        key.Key != ConsoleKey.Enter &&
                        !char.IsControl(key.KeyChar))
                    {
                        masked += key.KeyChar;

                        this.IO.Writer.Write("*");
                    }
                    else if (key.Key == ConsoleKey.Backspace && masked.Length > 0)
                    {
                        this.IO.Writer.Write("\b \b");
                        masked = masked.Substring(0, masked.Length - 1);
                    }
                    else if (key.Key == ConsoleKey.Enter)
                    {
                        this.IO.Writer.WriteLine();
                        break;
                    }
                }
                while (true);

                return masked;
            }
            finally
            {
                this.IO.HookCtrlC(false);
            }
        }
    }
}
