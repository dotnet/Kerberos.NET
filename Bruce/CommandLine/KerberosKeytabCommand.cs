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
using Humanizer;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("ktpass|kt|ktadd", Description = "KerberosKeytab")]
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

        [CommandLineParameter("d|delete", Description = "Delete")]
        public bool DeleteKey { get; set; }

        [CommandLineParameter("o|offline", Description = "Offline")]
        public bool Offline { get; set; }

        [CommandLineParameter("p|principal", Description = "Principal")]
        public override string PrincipalName { get; set; }

        [CommandLineParameter("password", Description = "Password")]
        public string Password { get; set; }

        [CommandLineParameter("s|salt", Description = "Salt")]
        public string Salt { get; set; }

        [CommandLineParameter("key", Description = "Key")]
        public string Key { get; set; }

        [CommandLineParameter("realm", Description = "Realm")]
        public override string Realm { get; set; }

        [CommandLineParameter("h|host", Description = "Host")]
        public string Host { get; set; }

        [CommandLineParameter("e|etype", Description = "EType")]
        public IEnumerable<EncryptionType> EncryptionTypes { get; private set; } = new List<EncryptionType>();

        [CommandLineParameter("ptype", Description = "PType")]
        public PrincipalNameType PrincipalNameType { get; set; } = PrincipalNameType.NT_SRV_INST;

        [CommandLineParameter("show", Description = "Show")]
        public bool ShowKey { get; set; }

        [CommandLineParameter("v|verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        [CommandLineParameter("verify", Description = "Verify")]
        public bool Verify { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.WriteLine();

            if (this.DeleteKey)
            {
                this.DeleteKeyFile();
            }
            else if (this.AddKey)
            {
                await this.AppendKeyToFile();
            }
            else
            {
                await this.DisplayKey();
            }

            return true;
        }

        private void DeleteKeyFile()
        {
            string file = this.GetKeytabFile();

            try
            {
                File.Delete(file);

                this.WriteProperties(new List<(string, object)> {
                    (SR.Resource("CommandLine_KerberosKeytab_FileDeleted"), file)
                });
            }
            catch (Exception ex)
            {
                this.WriteLineError(ex.Message);
            }
        }

        public override void DisplayHelp()
        {
            base.DisplayHelp();

            var props = new List<(string key, object value)>
            {
                (null, "Encryption Types")
            };

            var client = this.CreateClient();

            foreach (var etype in client.Configuration.Defaults.PermittedEncryptionTypes)
            {
                props.Add((etype.ToString().Humanize(LetterCasing.Title), etype));
            }

            WriteProperties(props);

            props = new List<(string key, object value)>
            {
                (null, "Principal Types")
            };

            foreach (PrincipalNameType ptype in Enum.GetValues(typeof(PrincipalNameType)))
            {
                props.Add((ptype.ToString().Humanize(LetterCasing.Title), ptype));
            }

            WriteProperties(props);
        }

        private async Task DisplayKey()
        {
            string file = this.GetKeytabFile();

            if (File.Exists(file))
            {
                await this.DumpKeytab(file);
            }
            else
            {
                this.WriteLineError(SR.Resource("CommandLine_KerberosKeytab_UnknownFile", file));
            }
        }

        private string GetKeytabFile()
        {
            if (string.IsNullOrWhiteSpace(this.KeytabFile))
            {
                this.KeytabFile = this.CreateClient().Configuration.Defaults.DefaultClientKeytabName;
            }

            return Environment.ExpandEnvironmentVariables(this.KeytabFile);
        }

        private async Task AppendKeyToFile()
        {
            var client = this.CreateClient();

            string file = this.GetKeytabFile();

            KeyTable keytab = null;

            if (File.Exists(file))
            {
                try
                {
                    var bytes = await File.ReadAllBytesAsync(file);

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

            bool added = false;

            IEnumerable<KrbETypeInfo2Entry> saltInfo = null;

            if (!this.Offline && string.IsNullOrWhiteSpace(this.Salt))
            {
                saltInfo = await PingForSalt(client);
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

            if (passwordBytes == null && key == null)
            {
                this.WriteLine();
                this.Write("Password: ");

                var password = this.ReadMasked();

                if (string.IsNullOrWhiteSpace(password))
                {
                    this.WriteLineError("Password or key must be set");
                    return;
                }

                this.WriteLine();

                passwordBytes = Encoding.Unicode.GetBytes(password);
            }

            var principal = KrbPrincipalName.FromString(this.PrincipalName, this.PrincipalNameType);

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

                var keyInfo = saltInfo?.FirstOrDefault(s => s.EType == etype);

                var kerbKey = new KerberosKey(
                    key: key,
                    password: passwordBytes,
                    etype: etype,
                    salt: keyInfo?.Salt ?? this.Salt,
                    iterationParams: keyInfo?.S2kParams?.ToArray(),
                    principal: Entities.PrincipalName.FromKrbPrincipalName(principal, this.Realm),
                    host: this.Host
                );

                keytab.Entries.Add(new KeyEntry(kerbKey));

                if (this.Verbose)
                {
                    var props = new List<(string, object)>
                    {
                        (null, $"Adding {etype}"),
                        ("PrincipalName", principal.FullyQualifiedName),
                        ("Salt", keyInfo?.Salt ?? kerbKey.Salt),
                        ("SaltFormat", kerbKey.SaltFormat)
                    };

                    this.WriteProperties(1, props);
                }

                added = true;
            }

            if (added)
            {
                using (var fs = new FileStream(file, FileMode.Create))
                using (var writer = new BinaryWriter(fs))
                {
                    keytab.Write(writer);
                    writer.Flush();
                }

                if (this.Verify)
                {
                    var success = await this.VerifyKeytab(principal);

                    if (!success)
                    {
                        return;
                    }
                }

                if (this.Verbose)
                {
                    this.WriteLine();
                }

                await this.DisplayKey();
            }
        }

        private async Task<bool> VerifyKeytab(KrbPrincipalName principal)
        {
            var kinit = new KerberosInitCommand(new CommandLineParameters())
            {
                Keytab = Environment.ExpandEnvironmentVariables(this.GetKeytabFile()),
                PrincipalName = principal.FullyQualifiedName,
                Realm = this.Realm,
                Verbose = this.Verbose
            };

            ((ICommand)kinit).IO = ((ICommand)this).IO;

            try
            {
                await kinit.Execute();

                return true;
            }
            catch (KerberosProtocolException kex)
            {
                this.WriteLineError("Validation Error: {Error} {EText}", kex.Error.ErrorCode, kex.Error.ETextWithoutCode());

                if (kex.Error.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_FAILED)
                {
                    this.WriteLineError(SR.Resource("CommandLine_KerberosKeytabCommand_VerifyFailedCred"));
                }

                return false;
            }
        }

        private async Task<IEnumerable<KrbETypeInfo2Entry>> PingForSalt(KerberosClient client)
        {
            var logger = this.Verbose ? this.IO.CreateVerboseLogger(labels: true) : NullLoggerFactory.Instance;

            var implicitUsername = false;

            if (string.IsNullOrWhiteSpace(this.PrincipalName))
            {
                this.PrincipalName = client.UserPrincipalName;
                implicitUsername = true;
            }

            if (string.IsNullOrWhiteSpace(this.PrincipalName))
            {
                return null;
            }

            var credential = new KerberosPasswordCredential(this.PrincipalName, "password not required for this");

            if (string.IsNullOrWhiteSpace(credential.UserName))
            {
                this.WriteLineWarning("UserPrincipalName is required");
                return null;
            }

            if (string.IsNullOrWhiteSpace(credential.Domain))
            {
                if (implicitUsername)
                {
                    credential = new KerberosPasswordCredential(this.PrincipalName, "password not required for this", this.Realm ?? this.DefaultRealm);
                }

                if (string.IsNullOrWhiteSpace(credential.Domain))
                {
                    this.WriteLineWarning("Domain could not be determined from username '{UserName}'", credential.UserName);
                    return null;
                }
            }

            var asReqMessage = KrbAsReq.CreateAsReq(credential, AuthenticationOptions.Renewable);

            var asReq = asReqMessage.EncodeApplication();

            var transport = new KerberosTransportSelector(
                new IKerberosTransport[]
                {
                    new TcpKerberosTransport(logger),
                    new UdpKerberosTransport(logger),
                    new HttpsKerberosTransport(logger)
                },
                client.Configuration,
                logger
            )
            {
                ConnectTimeout = TimeSpan.FromSeconds(5)
            };

            try
            {
                var asRep = await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);

                if (asRep?.Ticket != null)
                {
                    this.WriteLineError("Danger: The principal {PrincipalName} does not require pre-authentication", asRep.CName.FullyQualifiedName);
                    this.WriteLineError("Pre-authentication should be enabled ASAP");
                }
            }
            catch (KerberosProtocolException pex)
            {
                if (pex.Error.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                {
                    return pex.Error.DecodePreAuthentication()
                                    .Where(d => d.Type == PaDataType.PA_ETYPE_INFO2)
                                    .Select(d => d.DecodeETypeInfo2())
                                    .FirstOrDefault();
                }
            }

            return null;
        }

        private async Task DumpKeytab(string file)
        {
            var bytes = await File.ReadAllBytesAsync(file);

            var kt = new KeyTable(bytes);

            var props = new List<(string key, object value)>
            {
                ( "File", file ),
                ( SR.Resource("CommandLine_KerberosKeytab_FileVersion"), kt.FileVersion ),
                ( SR.Resource("CommandLine_KerberosKeytab_KerbVersion"), kt.KerberosVersion ),
                ( null, SR.Resource("CommandLine_KerberosKeytab_Keys") )
            };

            for (var i = 0; i < kt.Entries.Count; i++)
            {
                var key = kt.Entries.ElementAt(i);

                var keyBytes = key.Key.GetKey();

                props.Add((SR.Resource("CommandLine_KerberosKeytab_EType"), key.EncryptionType));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_PrincipalName"), key.Principal.FullyQualifiedName));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_KeyLength"), keyBytes.Length));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_Key"), this.ShowKey ? keyBytes : "[hidden]"));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_TimeStamp"), key.Timestamp));
                props.Add((SR.Resource("CommandLine_KerberosKeytab_KeyVersion"), key.Version));

                if (i < kt.Entries.Count - 1)
                {
                    props.Add(("", null));
                }
            }

            WriteProperties(props);
        }
    }
}
