// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Threading.Tasks;
#if WINDOWS
using System.Windows.Forms;
using KerbDump;
#endif

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kdecode", Description = "KerberosDecode")]
    public class KerberosDumpCommand : BaseCommand
    {
        static KerberosDumpCommand()
        {
#if WINDOWS
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
#endif
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

#if WINDOWS
            using (var form = new DecoderForm()
            {
                Ticket = this.Ticket,
                Persistent = string.IsNullOrWhiteSpace(this.Ticket)
            })
            {
                Application.Run(form);
            }
#endif

            return Task.FromResult(true);
        }
    }
}
