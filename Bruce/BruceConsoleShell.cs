// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    internal class BruceConsoleShell
    {
        private static readonly string Banner =
@"  ____                      
 | __ ) _ __ _   _  ___ ___ 
 |  _ \| '__| | | |/ __/ _ \
 | |_) | |  | |_| | (_|  __/  (___/=  
 |____/|_|   \__,_|\___\___|   7 7    


{BannerDescription} (v{Version})

(C) Copyright {BannerYear} .NET Foundation
";

        private readonly Stack<string> shellCommandPath = new();
        private readonly InputControl io;

        public BruceConsoleShell(InputControl io = null)
        {
            this.io = io ?? InputControl.Default();

            this.shellCommandPath.Push("bruce");
        }

        public bool Verbose { get; set; }

        public string ShellPrefix
        {
            get
            {
                var sb = new StringBuilder();

                foreach (var sh in this.shellCommandPath.Reverse())
                {
                    sb.Append($"{sh}/");
                }

                if (this.shellCommandPath.Any())
                {
                    sb.Remove(sb.Length - 1, 1);
                }

                sb.Append(">");

                return sb.ToString();
            }
        }

        public string LoadingModule { get; set; }

        public string CommandLine { get; set; }

        public bool Silent { get; set; }

        public async Task Start()
        {
            if (!this.Silent)
            {
                this.PrintBanner();
            }

            await this.StartLoop();
        }

        private async Task StartLoop()
        {
            bool attemptExternal = !string.IsNullOrWhiteSpace(this.CommandLine) || !string.IsNullOrWhiteSpace(this.LoadingModule);
            bool singleRun = false;

            while (true)
            {
                string commandLine = null;

                if (attemptExternal)
                {
                    commandLine = this.CommandLine;
                    attemptExternal = false;
                }

                if (string.IsNullOrWhiteSpace(commandLine) && string.IsNullOrWhiteSpace(this.LoadingModule))
                {
                    this.io.Writer.Write(this.ShellPrefix);
                    commandLine = this.io.Reader.ReadLine();
                }

                if (!string.IsNullOrWhiteSpace(this.LoadingModule))
                {
                    commandLine = $"{this.LoadingModule} {commandLine}".Trim();
                    singleRun = true;
                }

                var parameters = CommandLineParameters.Parse(commandLine);

                if (string.IsNullOrWhiteSpace(parameters?.Command))
                {
                    continue;
                }

                if (this.TryProcessSystemCommand(parameters, out bool exiting))
                {
                    if (exiting && !this.TryPopShell())
                    {
                        break;
                    }

                    continue;
                }

                try
                {
                    await this.ExecuteCommand(parameters);
                }
                catch (AggregateException agg)
                {
                    this.io.Writer.WriteLine();

                    foreach (var ex in agg.InnerExceptions)
                    {
                        this.io.Writer.WriteLine(ex.Message);
                    }
                }
                catch (Exception ex)
                {
                    if (ex is TargetInvocationException tex)
                    {
                        ex = tex.InnerException;
                    }

                    this.io.Writer.WriteLine();

                    if (this.Verbose)
                    {
                        this.io.Writer.WriteLine(ex);
                    }
                    else
                    {
                        this.io.Writer.WriteLine(ex.Message);
                    }

                    this.io.Writer.WriteLine();
                }

                if (singleRun)
                {
                    break;
                }
            }
        }

        private async Task ExecuteCommand(CommandLineParameters parameters)
        {
            var command = parameters.CreateCommandExecutor(this.io);

            if (command == null)
            {
                this.PrintUnknownCommand(parameters);
            }

            if (command != null)
            {
                var executed = await command.Execute();

                if (!executed)
                {
                    this.io.Writer.WriteLine();
                    command.DisplayHelp();
                }
            }

            this.io.Writer.WriteLine();
        }

        private bool TryProcessSystemCommand(CommandLineParameters parameters, out bool exiting)
        {
            exiting = false;

            switch (parameters.Command.ToLowerInvariant())
            {
                case "exit":
                case "quit":
                case "q":
                    exiting = true;
                    return true;

                case "clear":
                case "cls":
                    this.io.Clear();

                    return true;
            }

            return false;
        }

        private void PrintUnknownCommand(CommandLineParameters parameters)
        {
            this.io.Writer.WriteLine();
            this.io.Writer.WriteLine(string.Format(Strings.UnknownCommand, parameters.Command));
        }

        private bool TryPopShell()
        {
            this.shellCommandPath.TryPop(out _);

            return this.shellCommandPath.Count > 0;
        }

        private void PrintBanner()
        {
            var versionString = Assembly.GetEntryAssembly()
                                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                                .InformationalVersion
                                .ToString();

            var banner = Banner
                            .Replace("{Version}", versionString)
                            .Replace("{BannerDescription}", Strings.BannerDescription)
                            .Replace("{BannerYear}", DateTimeOffset.UtcNow.Year.ToString(CultureInfo.InvariantCulture));

            this.io.Writer.WriteLine(banner);
        }
    }
}
