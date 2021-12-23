// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Threading.Tasks;
using System.Windows.Forms;
using KerbDump;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kdecode", Description = "KerberosDecode")]
    public class KerberosDumpCommand : BaseCommand
    {
        static KerberosDumpCommand()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
        }

        public KerberosDumpCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }


        [CommandLineParameter("ticket", Description = "Ticket")]
        public string Ticket { get; set; }

        public override Task<bool> Execute()
        {
            if (!OSPlatform.IsWindows)
            {
                return Task.FromResult(false);
            }

            using (var form = new Form1()
            {
                Ticket = this.Ticket,
                Persistent = string.IsNullOrWhiteSpace(this.Ticket)
            })
            {
                Application.Run(form);
            }

            return Task.FromResult(true);
        }
    }
}
