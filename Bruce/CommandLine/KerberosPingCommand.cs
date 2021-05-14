// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kping", Description = "KerberosPing")]
    public class KerberosPing : BaseCommand
    {
        public KerberosPing(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("principal",
            FormalParameter = true,
            Required = true,
            Description = "UserPrincipalName")]
        public string UserPrincipalName { get; set; }

        [CommandLineParameter("verbose", Description = "Verbose")]
        public bool Verbose { get; protected set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            if (string.IsNullOrWhiteSpace(this.UserPrincipalName))
            {
                return false;
            }

            this.WriteLine();

            var client = this.CreateClient(verbose: this.Verbose);
            var logger = this.Verbose ? CreateVerboseLogger(labels: true) : NullLoggerFactory.Instance;

            var credential = new KerberosPasswordCredential(this.UserPrincipalName, "password not required for this");

            if (string.IsNullOrWhiteSpace(credential.UserName))
            {
                this.WriteLineWarning("UserPrincipalName is required");
                return false;
            }

            if (string.IsNullOrWhiteSpace(credential.Domain))
            {
                this.WriteLineWarning("Domain could not be determined from username '{UserName}'", credential.UserName);
                return false;
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
                WritePreAuthRequirement(credential, pex);
            }
            catch (AggregateException gex)
            {
                WriteFailure(logger, gex);
            }

            return true;
        }

        private void WriteFailure(ILoggerFactory logger, AggregateException gex)
        {
            if (this.Verbose)
            {
                this.WriteLine();
            }

            ILogger errorLog;

            if (this.Verbose)
            {
                errorLog = logger.CreateLogger("Error");
            }
            else
            {
                errorLog = CreateVerboseLogger().CreateLogger("Error");
            }

            foreach (var ex in gex.InnerExceptions)
            {
                errorLog.LogDebug(ex.Message);
            }
        }

        private void WritePreAuthRequirement(KerberosPasswordCredential credential, KerberosProtocolException pex)
        {
            if (this.Verbose)
            {
                this.WriteLine();
            }

            var errorCode = pex.Error.ErrorCode;

            this.WriteLine("   {ErrorCode}: {ErrorText}", pex.Error.ErrorCode, pex.Error.EText.Replace(pex.Error.ErrorCode.ToString() + ": ", ""));
            this.WriteLine("");

            if (!string.IsNullOrWhiteSpace(pex.Error.Realm))
            {
                this.WriteLine("   Realm: {Realm}", pex.Error.Realm);
            }

            if (pex.Error.CName != null)
            {
                this.WriteLine("   Client: {CName}", pex.Error.CName.FullyQualifiedName);
            }

            if (pex.Error.SName != null)
            {
                this.WriteLine("   Server: {SName}", pex.Error.SName.FullyQualifiedName);
            }

            this.WriteLine("");

            if (pex.Error.ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
            {
                return;
            }

            var paData = pex?.Error?.DecodePreAuthentication();

            if (paData != null)
            {
                foreach (var pa in paData)
                {
                    this.WriteLine("   - PA-Data Type: {PAType} ({PATypeValue})", pa.Type, (int)pa.Type);

                    if (pa.Type != PaDataType.PA_ETYPE_INFO2)
                    {
                        if (pa.Value.Length > 0)
                        {
                            this.WriteLine();
                            Hex.DumpHex(pa.Value, str => this.WriteLine("      {Value}", str), bytesPerLine: pa.Value.Length > 16 ? 16 : 8);
                        }
                        else
                        {
                            this.WriteLine("      {PaValue}", (string)null);
                        }

                        this.WriteLine("");

                        continue;
                    }

                    var etypeData = pa.DecodeETypeInfo2();

                    this.WriteLine("");
                    this.WriteLine("    - KDC Supported ETypes for principal {PrincipalName}", credential.UserName);
                    this.WriteLine("");

                    foreach (var etype in etypeData)
                    {
                        string s2k = null;

                        if (etype.S2kParams.HasValue)
                        {
                            s2k = Hex.DumpHex(etype.S2kParams.Value);
                        }

                        this.WriteLine("       Etype: {EType}", etype.EType);
                        this.WriteLine("        Salt: {Salt}", etype.Salt);
                        this.WriteLine("         S2K: {S2kParams}", s2k);
                        this.WriteLine("");
                    }
                }
            }
        }
    }
}
