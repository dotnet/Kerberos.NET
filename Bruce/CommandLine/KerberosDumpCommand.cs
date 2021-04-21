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
        public KerberosDumpCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        public override Task<bool> Execute()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            Application.Run(new Form1());


            return Task.FromResult(true);
        }
    }
}
