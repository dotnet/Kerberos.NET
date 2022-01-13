// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET
{
    public class TicketCacheEntry
    {
        public string Computed => GenerateKey(this.Container, this.Key);

        internal static string GenerateKey(string container = null, string key = null)
        {
            return $"kerberos-{container?.ToLowerInvariant()}-{key?.ToLowerInvariant()}";
        }

        public string Key { get; set; }

        public string Container { get; set; }

        public DateTimeOffset Expires { get; set; }

        public DateTimeOffset? RenewUntil { get; set; }

        public object Value { get; set; }

        public static TicketCacheEntry ConvertKrbCredToCacheEntry(KrbEncKrbCredPart credPart, KrbTicket ticket, KrbCredInfo ticketInfo)
        {
            var key = new byte[ticketInfo.Key.KeyValue.Length];
            ticketInfo.Key.KeyValue.CopyTo(key);

            var usage = KeyUsage.EncTgsRepPartSessionKey;

            var sessionKey = new KrbEncryptionKey { EType = ticketInfo.Key.EType, Usage = usage, KeyValue = key };

            var kdcRepData = new KrbEncTgsRepPart
            {
                AuthTime = ticketInfo.AuthTime ?? DateTimeOffset.UtcNow,
                EndTime = ticketInfo.EndTime ?? DateTimeOffset.MaxValue,
                Flags = ticketInfo.Flags,
                Key = sessionKey,
                Nonce = credPart.Nonce ?? 0,
                Realm = ticketInfo.Realm,
                RenewTill = ticketInfo.RenewTill,
                SName = ticketInfo.SName,
                StartTime = ticketInfo.StartTime ?? DateTimeOffset.MinValue,
                LastReq = Array.Empty<KrbLastReq>()
            };

            return new TicketCacheEntry
            {
                Key = ticket.SName.FullyQualifiedName,
                Expires = ticketInfo.EndTime ?? DateTimeOffset.MaxValue,
                RenewUntil = ticketInfo.RenewTill,
                Value = new KerberosClientCacheEntry
                {
                    SessionKey = sessionKey,
                    AuthTime = kdcRepData.AuthTime,
                    StartTime = kdcRepData.StartTime,
                    EndTime = kdcRepData.EndTime,
                    RenewTill = kdcRepData.RenewTill,
                    Flags = kdcRepData.Flags,
                    SName = kdcRepData.SName,
                    KdcResponse = new KrbTgsRep
                    {
                        Ticket = ticket,
                        CName = ticketInfo.PName,
                        CRealm = ticketInfo.Realm,
                        EncPart = KrbEncryptedData.Encrypt(kdcRepData.EncodeApplication(), sessionKey.AsKey(), usage)
                    }
                }
            };
        }
    }
}
