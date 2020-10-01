// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kt", Description = "KerberosKeytab")]
    public class KerberosKeytabCommand : BaseCommand
    {
        public KerberosKeytabCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("f|file", FormalParameter = true, Required = true, Description = "File")]
        public string KeytabFile { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.IO.Writer.WriteLine();

            if (File.Exists(this.KeytabFile))
            {
                var bytes = await File.ReadAllBytesAsync(this.KeytabFile);

                this.DumpKeytab(bytes);
            }
            else
            {
                this.IO.Writer.WriteLine(SR.Resource("CommandLine_KerberosKeytab_UnknownFile"));
                this.IO.Writer.WriteLine();
            }

            return true;
        }

        private void DumpKeytab(byte[] bytes)
        {
            var kt = new KeyTable(bytes);

            var props = new List<(string key, object value)>
            {
                ( SR.Resource("CommandLine_KerberosKeytab_FileVersion"), kt.FileVersion ),
                ( SR.Resource("CommandLine_KerberosKeytab_KerbVersion"), kt.KerberosVersion ),
                ( null, SR.Resource("CommandLine_KerberosKeytab_Keys") )
            };

            foreach (var key in kt.Entries)
            {
                var keyBytes = key.Key.GetKey().ToArray();
                var keyB64 = Convert.ToBase64String(keyBytes);

                props.Add((SR.Resource("CommandLine_KerberosKeytab_EType"), key.EncryptionType));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_PrincipalName"), key.Principal.FullyQualifiedName));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_KeyLength"), keyBytes.Length));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_Key"), keyB64));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_TimeStamp"), key.Timestamp));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_KeyVersion"), key.Version));
                props.Add(("", null));
            }

            var max = props.Max(p => p.key?.Length ?? 0) + 5;

            foreach (var (key, value) in props)
            {
                if (key is null)
                {
                    this.IO.Writer.WriteLine();
                    this.IO.Writer.WriteLine(value);
                    this.IO.Writer.WriteLine();
                    continue;
                }

                if (string.IsNullOrWhiteSpace(key))
                {
                    this.IO.Writer.WriteLine();
                    continue;
                }

                this.IO.Writer.Write($"{key}: ".PadLeft(max).PadRight(max));
                this.IO.Writer.WriteLine(value);
            }
        }
    }
}
