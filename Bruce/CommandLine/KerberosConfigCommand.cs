// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kconfig", Description = "KerberosConfig")]
    public class KerberosConfigCommand : BaseCommand
    {
        public KerberosConfigCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("c|config", Description = "Config")]
        public override string ConfigurationPath { get; set; }

        [CommandLineParameter("all", Description = "All")]
        public bool All { get; set; }

        [CommandLineParameter("defaults", Description = "Defaults")]
        public bool Defaults { get; set; }

        public override void DisplayHelp()
        {
            base.DisplayHelp();

            var uses = new[]
            {
                ("property=value", "CommandLine_Config_SetEquals"),
                ("property=", "CommandLine_Config_SetEqualsNull"),
                ("+property=value", "CommandLine_Config_SetEqualsPlus"),
                ("property value", "CommandLine_Config_SetEqualsSpace"),
                ("property", "CommandLine_Config_SetSpaceNull"),
                ("+property value", "CommandLine_Config_SetEqualsSpacePlus")
            };

            var max = uses.Max(u => u.Item1.Length) + 10;

            foreach (var use in uses)
            {
                this.WriteUsage(use.Item1, use.Item2, max);
            }

            this.WriteLine();
            this.WriteLine(2, SR.Resource("CommandLine_Config_DotHelp"));
            this.WriteLine(2, SR.Resource("CommandLine_Config_DotHelpEscaped"));
            this.WriteLine();
            this.WriteHeader(SR.Resource("CommandLine_Example"));
            this.WriteLine();
            this.WriteLine(2, "libdefaults.default_tgs_enctypes=aes");
            this.WriteLine(2, "realms.\"EXAMPLE.COM\".kdc=server.example.com");
            this.WriteLine(2, "+realms.\"EXAMPLE.COM\".kdc=server.example.com");

            this.WriteLine();
        }

        private void WriteUsage(string use, string desc, int padding)
        {
            var command = string.Format("{0} {1}", this.Parameters.Command, use);

            var label = command.PadLeft(10).PadRight(padding + 10);
            this.WriteLine(string.Format("   {0}{{Label}}", label), SR.Resource(desc));
        }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            if (this.Parameters.Parameters.Length > 0)
            {
                this.WriteConfiguration();
            }

            this.ListConfiguration();

            return true;
        }

        private void WriteConfiguration()
        {
            string configValue = null;
            bool configSet = false;

            if (!string.IsNullOrWhiteSpace(this.ConfigurationPath))
            {
                configValue = File.ReadAllText(this.ConfigurationPath);
                configSet = true;
            }

            var client = this.CreateClient(configValue);

            var config = ConfigurationSectionList.FromConfigObject(client.Configuration);

            bool changed = false;

            for (var i = 0; i < this.Parameters.Parameters.Length; i++)
            {
                var param = this.Parameters.Parameters[i];

                if (CommandLineParameters.IsParameter(param, out string designator))
                {
                    param = param[designator.Length..];
                }

                if (configSet && ("c".Equals(param, StringComparison.OrdinalIgnoreCase) || "config".Equals(param, StringComparison.OrdinalIgnoreCase)))
                {
                    i++;
                    continue;
                }
                else if ("all".Equals(param, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                bool? append = null;

                if (param.StartsWith("-"))
                {
                    append = false;
                }
                else if (param.StartsWith("+"))
                {
                    append = true;
                }

                if (append.HasValue)
                {
                    param = param[1..];
                }

                var split = param.Split('=');

                if (param.Contains("="))
                {
                    config.Set(split[0], split.Length > 1 ? split[1]?.Replace("\"", "") : null, append ?? false);
                }
                else if (i < this.Parameters.Parameters.Length - 1)
                {
                    var val = this.Parameters.Parameters[++i];

                    config.Set(param, val, append ?? false);
                }
                else
                {
                    config.Set(param, null, append ?? false);
                }

                changed = true;
            }

            if (changed)
            {
                // sanity check

                var verified = config.ToConfigObject();

                if (verified == null)
                {
                    throw new ArgumentException(SR.Resource("CommandLine_Config_Invalid"));
                }

                string path;

                if (configSet)
                {
                    path = this.ConfigurationPath;
                }
                else
                {
                    path = Krb5Config.DefaultUserConfiguration;
                }

                File.WriteAllText(path, Krb5ConfigurationSerializer.Serialize(config));
            }
        }

        private void ListConfiguration()
        {
            var client = this.CreateClient(this.Defaults ? Krb5Config.Default().Serialize() : null);

            var props = new List<(string, object)>()
            {
                (SR.Resource("CommandLine_ConfigPath"), Krb5Config.DefaultUserConfiguration),
            };

            if (!Krb5Config.DefaultUserConfiguration.Equals(this.ConfigurationPath, StringComparison.OrdinalIgnoreCase))
            {
                props.Add((SR.Resource("CommandLine_ConfigPath_Actual"), this.ConfigurationPath));
            }

            this.WriteLine();

            this.WriteProperties(props);

            var configStr = client.Configuration.Serialize(new Krb5ConfigurationSerializationConfig { SerializeDefaultValues = this.All || this.Defaults });

            this.WriteLine();
            this.WriteHeader(SR.Resource("ComandLine_KConfig_Config"));
            this.WriteLine();

            this.WriteLine("# ---------------- Configuration ----------------");
            this.WriteLine();

            foreach (var line in configStr.Split(Environment.NewLine))
            {
                if (line.Trim().StartsWith("["))
                {
                    this.WriteLineRaw(line + Environment.NewLine);
                }
                else
                {
                    this.WriteLineRaw("  " + line + Environment.NewLine);
                }
            }

            this.WriteLine();
            this.WriteLine("# -------------- End Configuration --------------");
        }
    }
}
