// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

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

        [CommandLineParameter("a|add", Description = "Add")]
        public bool AddKey { get; set; }

        [CommandLineParameter("p|principal", Description = "Principal")]
        public string PrincipalName { get; set; }

        [CommandLineParameter("password", Description = "Password")]
        public string Password { get; set; }

        [CommandLineParameter("key", Description = "Key")]
        public string Key { get; set; }

        [CommandLineParameter("realm", Description = "Realm")]
        public string Realm { get; set; }

        [CommandLineParameter("h|host", Description = "Host")]
        public string Host { get; set; }

        [CommandLineParameter("e|etype", Description = "EType")]
        public IEnumerable<EncryptionType> EncryptionTypes { get; private set; } = new List<EncryptionType>();

        [CommandLineParameter("ptype", Description = "PType")]
        public PrincipalNameType PrincipalNameType { get; set; } = PrincipalNameType.NT_SRV_INST;

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.IO.Writer.WriteLine();

            if (this.AddKey)
            {
                await this.AppendKeyToFile();
            }
            else
            {
                await this.DisplayKey();
            }

            return true;
        }

        private async Task DisplayKey()
        {
            if (File.Exists(this.KeytabFile))
            {
                var bytes = await File.ReadAllBytesAsync(this.KeytabFile);

                this.DumpKeytab(new KeyTable(bytes));
            }
            else
            {
                this.IO.Writer.WriteLine(SR.Resource("CommandLine_KerberosKeytab_UnknownFile"));
                this.IO.Writer.WriteLine();
            }
        }

        private async Task AppendKeyToFile()
        {
            KeyTable keytab = null;

            if (File.Exists(this.KeytabFile))
            {
                try
                {
                    var bytes = await File.ReadAllBytesAsync(this.KeytabFile);

                    keytab = new KeyTable(bytes);
                }
                catch
                {
                    keytab = null;
                }
            }

            if (keytab == null)
            {
                keytab = new KeyTable();
            }

            var etypes = this.EncryptionTypes;

            if (!(etypes?.Any() ?? false))
            {
                var clientForConfig = this.CreateClient();

                etypes = clientForConfig.Configuration.Defaults.DefaultTgsEncTypes;
            }

            foreach (var etype in etypes)
            {
                var existing = keytab.Entries.FirstOrDefault(e => e.EncryptionType == etype);

                if (existing != null)
                {
                    keytab.Entries.Remove(existing);
                }

                if (!CryptoService.SupportsEType(etype))
                {
                    continue;
                }

                byte[] key = null;

                if (!string.IsNullOrWhiteSpace(this.Key))
                {
                    key = Convert.FromBase64String(this.Key);
                }

                byte[] passwordBytes = null;

                if (!string.IsNullOrWhiteSpace(this.Password))
                {
                    passwordBytes = Encoding.Unicode.GetBytes(this.Password);
                }

                var principal = KrbPrincipalName.FromString(this.PrincipalName, this.PrincipalNameType);

                keytab.Entries.Add(
                    new KeyEntry(
                        new KerberosKey(
                            key: key,
                            password: passwordBytes,
                            etype: etype,
                            principal: Entities.PrincipalName.FromKrbPrincipalName(principal),
                            host: this.Host
                        )
                    )
                );
            }

            using (var fs = new FileStream(this.KeytabFile, FileMode.Create))
            using (var writer = new BinaryWriter(fs))
            {
                keytab.Write(writer);
                writer.Flush();
            }
        }

        private void DumpKeytab(KeyTable kt)
        {
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
