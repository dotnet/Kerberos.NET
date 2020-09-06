// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.Asn1;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;

namespace Kerberos.NET.CommandLine
{
    public abstract class BaseCommand : ICommand
    {
        private static readonly IEnumerable<string> ParameterDesignators = new[] { "/", "-", "--" };

        protected BaseCommand(CommandLineParameters parameters)
        {
            this.Parameters = parameters;

            this.ParseParameters();
        }

        public CommandControl IO { get; set; }

        public CommandLineParameters Parameters { get; }

        [CommandLineParameter("h|help", Description = "Help")]
        public bool Help { get; protected set; }

        public virtual Task<bool> Execute()
        {
            if (this.Help)
            {
                this.DisplayHelp();

                return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }

        public void DisplayHelp()
        {
            this.IO.Writer.Write("Usage: {0} ", this.Parameters.Command);

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
                    this.IO.Writer.WriteLine(attr.Name);
                }

                WriteProperty(prop, attr);
            }

            var max = props.Max(p => p.Item2.Name.Length) + 20;

            this.IO.Writer.WriteLine();
            this.IO.Writer.WriteLine();

            foreach (var prop in props)
            {
                WritePropertyDescription(prop.Item1, prop.Item2, this.GetType().Name, padding: max);
                this.IO.Writer.WriteLine();
            }

            this.IO.Writer.WriteLine();
        }

        readonly StringBuilder sb = new StringBuilder();

        private void WriteProperty(PropertyInfo prop, CommandLineParameterAttribute attr)
        {
            var names = attr.Name.Split('|');

            var hasValue = prop.PropertyType != typeof(bool);

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

                sb.AppendFormat(" ");
            }

            this.IO.Writer.Write(sb.ToString());
            sb.Clear();
        }

        private void WritePropertyDescription(PropertyInfo prop, CommandLineParameterAttribute attr, string commandPrefix, int padding)
        {
            var names = attr.Name.Split('|');

            var hasValue = prop.PropertyType != typeof(bool);

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
            sb.Clear();
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
            bool usedValue = true;

            if (prop.PropertyType == typeof(bool))
            {
                if (!bool.TryParse(nextValue, out bool result))
                {
                    result = !char.IsUpper(param[0]);
                    usedValue = false;
                }

                prop.SetValue(instance, result);
            }
            else if (prop.PropertyType == typeof(TimeSpan) || prop.PropertyType == typeof(TimeSpan?))
            {
                var ts = TimeSpanDurationSerializer.Parse(nextValue);
                prop.SetValue(instance, ts);
            }
            else
            {
                prop.SetValue(instance, nextValue);
            }

            return usedValue;
        }

        private static bool IsParameter(string parameter, out string designator)
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
