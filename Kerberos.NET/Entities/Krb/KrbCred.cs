// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbCred
    {
        public KrbCred()
        {
            this.ProtocolVersionNumber = 5;
            this.MessageType = MessageType.KRB_CRED;
        }

        public KrbEncKrbCredPart Validate()
        {
            if (this.Tickets is null)
            {
                throw new InvalidOperationException("The Krb-Cred structure requires a sequence of tickets");
            }

            if (this.EncryptedPart.EType != EncryptionType.NULL)
            {
                throw new InvalidOperationException("Import only supports unencrypted EncKrbCredPart structures");
            }

            var credPart = KrbEncKrbCredPart.DecodeApplication(this.EncryptedPart.Cipher);

            if (this.Tickets.Length != credPart.TicketInfo.Length)
            {
                throw new InvalidOperationException($"KrbCred Ticket count {this.Tickets.Length} mismatch with KrbCredInfo count {credPart.TicketInfo.Length}");
            }

            return credPart;
        }

        public static KrbCred WrapTicket(KrbTicket ticket, KrbEncTicketPart encTicketPart)
        {
            if (ticket is null)
            {
                throw new ArgumentNullException(nameof(ticket));
            }

            if (encTicketPart is null)
            {
                throw new ArgumentNullException(nameof(encTicketPart));
            }

            KerberosConstants.Now(out DateTimeOffset timestamp, out int usec);

            var encPart = new KrbEncKrbCredPart
            {
                Timestamp = timestamp,
                USec = usec,
                TicketInfo = new[]
                {
                    new KrbCredInfo
                    {
                        Key = encTicketPart.Key,
                        AuthTime = encTicketPart.AuthTime,
                        EndTime = encTicketPart.EndTime,
                        Flags = encTicketPart.Flags,
                        PName = encTicketPart.CName,
                        Realm = encTicketPart.CRealm,
                        RenewTill = encTicketPart.RenewTill,
                        SName = ticket.SName,
                        SRealm = ticket.Realm,
                        StartTime = encTicketPart.StartTime,
                    }
                }
            };

            var cred = new KrbCred
            {
                EncryptedPart = new KrbEncryptedData { Cipher = encPart.EncodeApplication() },
                Tickets = new[] { ticket },
            };

            return cred;
        }
    }
}