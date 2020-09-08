// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kdestroy", Description = "KerberosDestroy")]
    public class KerberosDestroyCommand : BaseCommand
    {
        public KerberosDestroyCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }


        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            var client = this.CreateClient();

            this.PurgeTickets(client.Configuration.Defaults.DefaultCCacheName);

            return true;
        }

        private void PurgeTickets(string cache)
        {
            TicketCacheBase.TryParseCacheType(cache, out _, out string path);

            try
            {
                File.Delete(Environment.ExpandEnvironmentVariables(path));
                this.IO.Writer.WriteLine(SR.Resource("CommandLine_KerberosDestroy_Deleted"));
            }
            catch (Exception ex)
            {
                this.IO.Writer.Write("{0}: ", SR.Resource("CommandLine_KerberosDestroy_Error"));
                this.IO.Writer.WriteLine(ex.Message);
            }

            this.IO.Writer.WriteLine();
        }
    }
}
