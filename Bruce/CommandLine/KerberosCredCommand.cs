// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kcred|cred", Description = "KerberosCred")]
    public class KerberosCredCommand : BaseCommand
    {
        public KerberosCredCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("v|verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        [CommandLineParameter("c|cache", Description = "Cache")]
        public string Cache { get; set; }

        [CommandLineParameter("i|import", Description = "Import")]
        public string ImportData { get; set; }

        [CommandLineParameter("f|file", Description = "File")]
        public string FilePath { get; set; }

        [CommandLineParameter("e|export", Description = "Export")]
        public string ExportSpn { get; set; }

        [CommandLineParameter("d|decode", Description = "Decode")]
        public string DecodeData { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            this.WriteLine();

            if (!string.IsNullOrWhiteSpace(this.DecodeData) || !string.IsNullOrWhiteSpace(this.FilePath) && string.IsNullOrWhiteSpace(this.ImportData))
            {
                this.DecodeKrbCred();
                return true;
            }

            var client = this.CreateClient(verbose: this.Verbose);

            if (!string.IsNullOrWhiteSpace(this.Cache))
            {
                client.Configuration.Defaults.DefaultCCacheName = this.Cache;
            }

            if (!string.IsNullOrWhiteSpace(this.ImportData))
            {
                await this.ImportTicket(client);
            }

            if (!string.IsNullOrWhiteSpace(this.ExportSpn))
            {
                this.ExportTicket(client);
            }

            if (string.IsNullOrWhiteSpace(this.ImportData) &&
                string.IsNullOrWhiteSpace(this.ExportSpn) &&
                string.IsNullOrWhiteSpace(this.DecodeData))
            {
                this.WriteLineError("Specify --import, --export, --decode, or --file to decode a KRB-CRED");
                return false;
            }

            return true;
        }

        private void DecodeKrbCred()
        {
            byte[] bytes = null;

            if (!string.IsNullOrWhiteSpace(this.FilePath))
            {
                var path = Environment.ExpandEnvironmentVariables(this.FilePath);

                if (!File.Exists(path))
                {
                    this.WriteLineError("File not found: {File}", path);
                    return;
                }

                bytes = File.ReadAllBytes(path);

                // Check if file content is base64
                try
                {
                    var text = System.Text.Encoding.UTF8.GetString(bytes).Trim();
                    bytes = Convert.FromBase64String(text);
                }
                catch
                {
                    // Not base64, use raw bytes
                }
            }
            else if (!string.IsNullOrWhiteSpace(this.DecodeData))
            {
                try
                {
                    bytes = Convert.FromBase64String(this.DecodeData.Trim());
                }
                catch (FormatException)
                {
                    this.WriteLineError("Input is not valid base64");
                    return;
                }
            }

            if (bytes == null || bytes.Length == 0)
            {
                this.WriteLineError("No data to decode");
                return;
            }

            KrbCred cred;

            try
            {
                cred = KrbCred.DecodeApplication(bytes);
            }
            catch (Exception ex)
            {
                this.WriteLineError("Failed to decode KRB-CRED: {Error}", ex.Message);
                return;
            }

            this.DisplayKrbCred(cred);
        }

        private void DisplayKrbCred(KrbCred cred)
        {
            var props = new List<(string, object)>
            {
                (null, "KRB-CRED"),
                ("Protocol Version", cred.ProtocolVersionNumber),
                ("Message Type", cred.MessageType),
                ("Tickets", cred.Tickets?.Length ?? 0),
                ("Encrypted Part EType", cred.EncryptedPart?.EType),
            };

            this.WriteProperties(props);
            this.WriteLine();

            if (cred.Tickets != null)
            {
                for (var i = 0; i < cred.Tickets.Length; i++)
                {
                    var ticket = cred.Tickets[i];

                    var ticketProps = new List<(string, object)>
                    {
                        (null, $"Ticket #{i}"),
                        ("Realm", ticket.Realm),
                        ("Server Name", ticket.SName?.FullyQualifiedName),
                        ("Encryption Type", ticket.EncryptedPart?.EType),
                        ("Key Version", ticket.EncryptedPart?.KeyVersionNumber),
                    };

                    this.WriteProperties(ticketProps);
                    this.WriteLine();
                }
            }

            if (cred.EncryptedPart?.EType == EncryptionType.NULL)
            {
                try
                {
                    var credPart = cred.Validate();
                    this.DisplayCredPart(credPart);
                }
                catch (Exception ex)
                {
                    if (this.Verbose)
                    {
                        this.WriteLineWarning("Could not decode EncKrbCredPart: {Error}", ex.Message);
                    }
                }
            }
        }

        private void DisplayCredPart(KrbEncKrbCredPart credPart)
        {
            if (credPart.TicketInfo == null)
            {
                return;
            }

            for (var i = 0; i < credPart.TicketInfo.Length; i++)
            {
                var info = credPart.TicketInfo[i];

                var infoProps = new List<(string, object)>
                {
                    (null, $"Credential Info #{i}"),
                    ("Principal", info.PName?.FullyQualifiedName),
                    ("Realm", info.Realm),
                    ("Server", info.SName?.FullyQualifiedName),
                    ("Server Realm", info.SRealm),
                    ("Key Type", info.Key?.EType),
                    ("Flags", info.Flags),
                    ("Auth Time", info.AuthTime),
                    ("Start Time", info.StartTime),
                    ("End Time", info.EndTime),
                    ("Renew Till", info.RenewTill),
                };

                this.WriteProperties(infoProps);
                this.WriteLine();
            }
        }

        private async Task ImportTicket(KerberosClient client)
        {
            byte[] bytes;

            if (!string.IsNullOrWhiteSpace(this.FilePath))
            {
                var path = Environment.ExpandEnvironmentVariables(this.FilePath);

                if (!File.Exists(path))
                {
                    this.WriteLineError("File not found: {File}", path);
                    return;
                }

                bytes = File.ReadAllBytes(path);
            }
            else
            {
                try
                {
                    bytes = Convert.FromBase64String(this.ImportData.Trim());
                }
                catch (FormatException)
                {
                    this.WriteLineError("Import data is not valid base64");
                    return;
                }
            }

            KrbCred cred;

            try
            {
                cred = KrbCred.DecodeApplication(bytes);
            }
            catch (Exception ex)
            {
                this.WriteLineError("Failed to decode KRB-CRED: {Error}", ex.Message);
                return;
            }

            for (var i = 0; i < cred.Tickets.Length; i++)
            {
                var ticket = cred.Tickets[i];
                var spn = ticket.SName?.FullyQualifiedName ?? "unknown";

                this.WriteLine("Importing ticket for {Spn}", spn);
            }

            client.ImportCredential(cred);

            this.WriteLine();
            this.WriteLine("Imported {Count} ticket(s)", cred.Tickets.Length);
        }

        private void ExportTicket(KerberosClient client)
        {
            var entry = client.Cache.GetCacheItem<KerberosClientCacheEntry>(this.ExportSpn);

            if (entry == null)
            {
                this.WriteLineError("No cached ticket found for {Spn}", this.ExportSpn);
                return;
            }

            var ticket = entry.KdcResponse?.Ticket;

            if (ticket == null)
            {
                this.WriteLineError("Cache entry has no ticket for {Spn}", this.ExportSpn);
                return;
            }

            var credInfo = new KrbCredInfo
            {
                Key = entry.SessionKey,
                Realm = entry.KdcResponse.CRealm,
                PName = entry.KdcResponse.CName,
                Flags = entry.Flags,
                AuthTime = entry.AuthTime,
                StartTime = entry.StartTime,
                EndTime = entry.EndTime,
                RenewTill = entry.RenewTill,
                SName = ticket.SName,
                SRealm = ticket.Realm,
            };

            var krbCred = KrbCred.WrapTicket(ticket, credInfo);
            var encoded = krbCred.EncodeApplication();

            if (!string.IsNullOrWhiteSpace(this.FilePath))
            {
                var path = Environment.ExpandEnvironmentVariables(this.FilePath);
                File.WriteAllBytes(path, encoded.ToArray());
                this.WriteLine("Exported ticket to {File}", path);
            }
            else
            {
                this.WriteHeader("KRB-CRED (base64)");
                this.WriteLine(1, "{Data}", Convert.ToBase64String(encoded.ToArray()));
            }

            this.WriteLine();
        }
    }
}
