// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("ktoken|token", Description = "KerberosTokenDecode")]
    public class KerberosTokenDecodeCommand : BaseCommand
    {
        public KerberosTokenDecodeCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("token", FormalParameter = true, Description = "Token")]
        public string Token { get; set; }

        [CommandLineParameter("v|verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        [CommandLineParameter("raw", Description = "Raw")]
        public bool Raw { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            if (string.IsNullOrWhiteSpace(this.Token))
            {
                this.WriteLineError("A base64-encoded token is required");
                return false;
            }

            this.WriteLine();

            var tokenString = this.Token.Trim();

            // Strip common prefixes
            foreach (var prefix in new[] { "Authorization: Negotiate ", "Negotiate ", "Authorization: " })
            {
                if (tokenString.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    tokenString = tokenString.Substring(prefix.Length).Trim();
                    break;
                }
            }

            byte[] bytes;

            try
            {
                bytes = Convert.FromBase64String(tokenString);
            }
            catch (FormatException)
            {
                this.WriteLineError("Input is not valid base64");
                return false;
            }

            var data = new ReadOnlyMemory<byte>(bytes);

            if (this.Raw)
            {
                this.WriteHeader("Raw Token Bytes");
                this.WriteLine(1, "{Hex}", Hex.DumpHex(bytes));
                this.WriteLine();
            }

            try
            {
                this.DecodeToken(data);
            }
            catch (Exception ex)
            {
                this.WriteLineError("Failed to decode token: {Error}", ex.Message);

                if (this.Verbose)
                {
                    this.WriteLine(1, "{StackTrace}", ex.StackTrace);
                }
            }

            return true;
        }

        private void DecodeToken(ReadOnlyMemory<byte> data)
        {
            // Try SPNEGO first
            if (NegotiationToken.CanDecode(data))
            {
                var gssToken = GssApiToken.Decode(data);

                var props = new List<(string, object)>
                {
                    (null, "GSS-API Token"),
                    ("Mechanism", gssToken.ThisMech.Value),
                    ("Mechanism Name", GetMechName(gssToken.ThisMech.Value)),
                };

                if (gssToken.MessageType != default)
                {
                    props.Add(("Message Type", gssToken.MessageType));
                }

                this.WriteProperties(props);
                this.WriteLine();

                if (gssToken.ThisMech.Value == MechType.SPNEGO ||
                    gssToken.ThisMech.Value == MechType.NEGOEX)
                {
                    this.DecodeSpnego(gssToken.Token);
                }
                else if (gssToken.Token.Length > 0)
                {
                    this.DecodeKerberosMessage(gssToken.Token);
                }

                return;
            }

            // Try raw Kerberos
            if (KrbApReq.CanDecode(data))
            {
                this.DecodeApReq(data);
                return;
            }

            if (KrbApRep.CanDecode(data))
            {
                this.DecodeApRep(data);
                return;
            }

            if (KrbError.CanDecode(data))
            {
                this.DecodeKrbError(data);
                return;
            }

            this.WriteLineWarning("Unable to determine token type");
        }

        private void DecodeSpnego(ReadOnlyMemory<byte> data)
        {
            var negToken = NegotiationToken.Decode(data);

            if (negToken.InitialToken != null)
            {
                var init = negToken.InitialToken;

                this.WriteHeader("SPNEGO NegTokenInit");

                if (init.MechTypes?.Length > 0)
                {
                    this.WriteLine(1, "Mechanism Types:");

                    foreach (var mech in init.MechTypes)
                    {
                        this.WriteLine(2, "  {Mech} ({MechName})", mech.Value, GetMechName(mech.Value));
                    }

                    this.WriteLine();
                }

                if (init.MechToken.HasValue && init.MechToken.Value.Length > 0)
                {
                    this.WriteHeader("Inner MechToken");
                    this.DecodeKerberosMessage(init.MechToken.Value);
                }
            }

            if (negToken.ResponseToken != null)
            {
                var resp = negToken.ResponseToken;

                var props = new List<(string, object)>
                {
                    (null, "SPNEGO NegTokenResp"),
                    ("State", resp.State),
                };

                if (resp.SupportedMech != null)
                {
                    props.Add(("Supported Mech", $"{resp.SupportedMech.Value} ({GetMechName(resp.SupportedMech.Value)})"));
                }

                this.WriteProperties(props);
                this.WriteLine();

                if (resp.ResponseToken.HasValue && resp.ResponseToken.Value.Length > 0)
                {
                    this.WriteHeader("Inner ResponseToken");
                    this.DecodeKerberosMessage(resp.ResponseToken.Value);
                }
            }
        }

        private void DecodeKerberosMessage(ReadOnlyMemory<byte> data)
        {
            if (KrbApReq.CanDecode(data))
            {
                this.DecodeApReq(data);
            }
            else if (KrbApRep.CanDecode(data))
            {
                this.DecodeApRep(data);
            }
            else if (KrbError.CanDecode(data))
            {
                this.DecodeKrbError(data);
            }
            else
            {
                this.WriteLineWarning("Inner token is not a recognized Kerberos message type");

                if (this.Verbose)
                {
                    this.WriteLine(1, "{Hex}", Hex.DumpHex(data.ToArray()));
                }
            }
        }

        private void DecodeApReq(ReadOnlyMemory<byte> data)
        {
            var apReq = KrbApReq.DecodeApplication(data);

            var props = new List<(string, object)>
            {
                (null, "AP-REQ"),
                ("Protocol Version", apReq.ProtocolVersionNumber),
                ("Message Type", apReq.MessageType),
                ("AP Options", apReq.ApOptions),
            };

            this.WriteProperties(props);
            this.WriteLine();

            var ticket = apReq.Ticket;

            var ticketProps = new List<(string, object)>
            {
                (null, "Ticket"),
                ("Ticket Version", ticket.TicketNumber),
                ("Realm", ticket.Realm),
                ("Server Name", ticket.SName?.FullyQualifiedName),
                ("Encryption Type", ticket.EncryptedPart.EType),
                ("Key Version", ticket.EncryptedPart.KeyVersionNumber),
            };

            this.WriteProperties(ticketProps);
            this.WriteLine();

            if (this.Verbose)
            {
                this.WriteLine(1, "Authenticator EType: {EType}", apReq.Authenticator.EType);
            }
        }

        private void DecodeApRep(ReadOnlyMemory<byte> data)
        {
            var apRep = KrbApRep.DecodeApplication(data);

            var props = new List<(string, object)>
            {
                (null, "AP-REP"),
                ("Protocol Version", apRep.ProtocolVersionNumber),
                ("Message Type", apRep.MessageType),
                ("Encryption Type", apRep.EncryptedPart.EType),
            };

            this.WriteProperties(props);
        }

        private void DecodeKrbError(ReadOnlyMemory<byte> data)
        {
            var error = KrbError.DecodeApplication(data);

            var props = new List<(string, object)>
            {
                (null, "KRB-ERROR"),
                ("Error Code", error.ErrorCode),
                ("Error Text", error.EText),
                ("Server Time", error.STime),
                ("Client Time", error.CTime),
                ("Realm", error.Realm),
                ("Server Name", error.SName?.FullyQualifiedName),
                ("Client Name", error.CName?.FullyQualifiedName),
            };

            this.WriteProperties(props);
        }

        private static string GetMechName(string oid)
        {
            return oid switch
            {
                MechType.SPNEGO => "SPNEGO",
                MechType.NEGOEX => "NEGOEX",
                MechType.KerberosGssApi => "Kerberos 5",
                MechType.KerberosV5Legacy => "Kerberos 5 (Legacy)",
                MechType.KerberosUser2User => "Kerberos User2User",
                MechType.IAKerb => "IAKerb",
                MechType.NTLM => "NTLM",
                _ => "Unknown"
            };
        }
    }
}
