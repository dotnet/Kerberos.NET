using System;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var argvIndex = Environment.CommandLine.IndexOf(' ');

            string argv = null;

            if (argvIndex >= 0)
            {
                argv = Environment.CommandLine.Substring(argvIndex);
            }

            var shell = new BruceConsoleShell()
            {
                CommandLine = argv
            };

            await shell.Start();
        }
    }
}
