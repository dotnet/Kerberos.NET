// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kping|ping", Description = "KerberosPing")]
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
        public override string PrincipalName { get; set; }

        [CommandLineParameter("realm", Description = "Realm")]
        public override string Realm { get; set; }

        [CommandLineParameter("verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.WriteLine();

            var client = this.CreateClient(verbose: this.Verbose);
            var logger = this.Verbose ? this.IO.CreateVerboseLogger(labels: true) : NullLoggerFactory.Instance;

            var implicitUsername = false;

            if (string.IsNullOrWhiteSpace(this.PrincipalName))
            {
                this.PrincipalName = client.UserPrincipalName;
                implicitUsername = true;
            }

            if (string.IsNullOrWhiteSpace(this.PrincipalName))
            {
                return false;
            }

            var credential = new KerberosPasswordCredential(this.PrincipalName, "password not required for this");

            if (string.IsNullOrWhiteSpace(credential.UserName))
            {
                this.WriteLineWarning("UserPrincipalName is required");
                return false;
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
                    return false;
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
                WritePreAuthRequirement(credential, pex);
            }
            catch (AggregateException gex)
            {
                WriteFailure(logger, gex);
            }
            catch (Exception ex)
            {
                logger.CreateLogger("exception").LogCritical(ex.ToString());
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
                errorLog = this.IO.CreateVerboseLogger().CreateLogger("Error");
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

            this.WriteLine(1, "{ErrorCode}: {ErrorText}", pex.Error.ErrorCode, pex.Error.ETextWithoutCode());
            this.WriteLine();

            if (!string.IsNullOrWhiteSpace(pex.Error.Realm))
            {
                this.WriteLine(1, "Realm: {Realm}", pex.Error.Realm);
            }

            if (pex.Error.CName != null)
            {
                this.WriteLine(1, "Client: {CName}", pex.Error.CName.FullyQualifiedName);
            }

            if (pex.Error.SName != null)
            {
                this.WriteLine(1, "Server: {SName}", pex.Error.SName.FullyQualifiedName);
            }

            this.WriteLine();

            if (pex.Error.ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
            {
                return;
            }

            var paData = pex?.Error?.DecodePreAuthentication();

            if (paData != null)
            {
                int index = 0;

                foreach (var pa in paData.OrderBy(p => p.Type != PaDataType.PA_ETYPE_INFO2).ThenBy(p => p.Type))
                {
                    index++;

                    this.WriteLine(2, "- PA-Data Type: {PAType} ({PATypeValue})", pa.Type, (int)pa.Type);

                    var isEtype = pa.Type == PaDataType.PA_ETYPE_INFO2;

                    if (isEtype)
                    {
                        var etypeData = pa.DecodeETypeInfo2();

                        this.WriteLine(3, "KDC Supported ETypes for principal {PrincipalName}", credential.UserName);
                        this.WriteLine();

                        foreach (var etype in etypeData)
                        {
                            this.WriteLine(4, "Etype: {EType}", etype.EType);
                            this.WriteLine(4, " Salt: {Salt}", etype.Salt);
                            this.WriteLine(4, "  S2K: {S2kParams}", etype.S2kParams ?? Array.Empty<byte>());
                            this.WriteLine();
                        }
                    }

                    if (!isEtype || this.Verbose)
                    {
                        if (pa.Value.Length > 0)
                        {
                            if (!isEtype)
                            {
                                this.WriteLine();
                            }

                            this.WriteLine(3, pa.Value);
                        }
                        else
                        {
                            this.WriteLine(3, (object)null);

                            if (index < paData.Count())
                            {
                                this.WriteLine();
                            }
                        }
                    }
                }
            }
        }
    }
}
