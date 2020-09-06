﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Kerberos.NET.CommandLine
{
    public class CommandLineParameters
    {
        public static CommandLineParameters Parse(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                return null;
            }

            var split = commandLine.Split(new char[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);

            if (split.Length == 0)
            {
                return null;
            }

            return new CommandLineParameters
            {
                Command = split[0],
                Parameters = split.Length > 1 ? ParseArguments(split[1]) : Array.Empty<string>()
            };
        }

        private static string[] ParseArguments(string argv)
        {
            argv = argv.Trim();

            bool inQuote = false;
            bool wasInQuote = false;

            int start = 0;

            var args = new List<string>();

            for (var i = 0; i < argv.Length; i++)
            {
                if (argv[i] == '"')
                {
                    wasInQuote = inQuote;
                    inQuote = !inQuote;

                    if (inQuote)
                    {
                        start += 1;
                    }
                }

                bool end = argv.Length - 1 == i;

                if ((argv[i] == ' ' && !inQuote) || end)
                {
                    var length = i + 1 - start;

                    if (wasInQuote)
                    {
                        length--;
                        wasInQuote = false;
                    }

                    if (!end)
                    {
                        length--;
                    }

                    args.Add(argv.Substring(start, length));
                    start = i + 1;
                }
            }

            return args.ToArray();
        }

        public string Command { get; set; }

        public string[] Parameters { get; set; }

        public ICommand CreateCommandExecutor(CommandControl io)
        {
            string commandValue = this.Command;

            return  CommandLoader.CreateCommandExecutor(commandValue, this, io);
        }

        public override string ToString()
        {
            if (string.IsNullOrWhiteSpace(this.Command) && this.Parameters == null)
            {
                return base.ToString();
            }

            var sb = new StringBuilder();

            if (!string.IsNullOrWhiteSpace(this.Command))
            {
                sb.Append(this.Command);
                sb.Append(" ");
            }

            for (var i = 0; i < this.Parameters.Length; i++)
            {
                var param = this.Parameters[i];

                if (param.Contains(' '))
                {
                    sb.AppendFormat("\"{0}\"", param);
                }
                else
                {
                    sb.Append(param);
                }

                if (i < this.Parameters.Length - 1)
                {
                    sb.Append(" ");
                }
            }

            return sb.ToString();
        }
    }
}
