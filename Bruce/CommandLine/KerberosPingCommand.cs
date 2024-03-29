﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kping|ping", Description = "KerberosPing")]
    public class KerberosPingCommand : BaseCommand
    {
        public KerberosPingCommand(CommandLineParameters parameters)
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
            try
            {
                var result = await KerberosPing.Ping(credential, client.Configuration, logger);

                if (result.AsRep != null)
                {
                    this.IO.WriteAsColor("  Danger: ", ConsoleColor.Red);
                    this.WriteLine("The principal {PrincipalName} does not require pre-authentication", result.AsRep.CName.FullyQualifiedName);
                    this.WriteLine();
                    this.WriteLine(1, "Pre-authentication should be enabled ASAP");
                }

                else
                {
                    this.WritePreAuthRequirement(credential, result.Error, result.AsReq);
                }
            }
            catch (AggregateException gex)
            {
                this.WriteFailure(logger, gex);
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

        private void WritePreAuthRequirement(KerberosPasswordCredential credential, KrbError error, KrbAsReq asreq)
        {
            if (this.Verbose)
            {
                this.WriteLine();
            }

            this.WriteLine(1, "{ErrorCode}: {ErrorText}", error.ErrorCode, error.ETextWithoutCode() ?? "(no message)");
            this.WriteLine();

            if (!string.IsNullOrWhiteSpace(error.Realm))
            {
                this.WriteLine(1, " Realm: {Realm}", error.Realm);
            }

            if (error.CName != null)
            {
                this.WriteLine(1, " Client: {CName}", error.CName.FullyQualifiedName);
            }

            if (error.SName != null)
            {
                this.WriteLine(1, "Server: {SName}", error.SName.FullyQualifiedName);
            }

            this.WriteLine();

            if (error.ErrorCode == KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP)
            {
                this.IO.WriteAsColor("   Error: ", ConsoleColor.Red);
                this.WriteLine("Client requested the following ETypes but the KDC cannot support any of them.");
                this.WriteLine();

                bool first = true;

                foreach (var etype in asreq.Body.EType)
                {
                    var label = first ? "ETypes: " : "        ";

                    this.WriteLine(1, label + "{ETypes}", etype);

                    first = false;
                }

                if (!asreq.Body.EType.Contains(EncryptionType.RC4_HMAC_NT))
                {
                    this.WriteLine();
                    this.IO.WriteAsColor("    Note: ", ConsoleColor.Green);
                    this.WriteLine("RC4 is not enabled on the client. The KDC likely only supports RC4 for this user.");
                }

                return;
            }

            if (error.ErrorCode == KerberosErrorCode.KDC_ERR_POLICY &&
                error.EData.HasValue &&
                KrbErrorData.CanDecode(error.EData.Value))
            {
                var decoded = KrbErrorData.Decode(error.EData.Value);
                var ext = decoded.DecodeExtendedError();

                this.WriteLine(1, error.EText);
                this.WriteLine();
                this.WriteLine(1, "Status: {Status}", ext.Status);
                this.WriteLine(1, " Flags: {Flags}", ext.Flags);

                return;
            }

            if (error.ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
            {
                if (error.EData.HasValue)
                {
                    this.WriteLine(1, "{EData}", error.EData);
                }

                return;
            }

            var paData = error?.DecodePreAuthentication();

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
