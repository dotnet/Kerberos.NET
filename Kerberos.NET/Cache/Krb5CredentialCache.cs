// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Client
{
    [DebuggerDisplay("{Credentials}")]
    public class Krb5CredentialCache
    {
        private const byte Magic = 5;
        private const byte ExpectedVersion3 = 3;
        private const byte ExpectedVersion4 = 4;

        /* The format of this file is described here: https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html
         *
         * The first byte of the file always has the value 5, and the value of the second byte contains the version number (1 through 4).
         *
         * Versions 3 and 4 always use big-endian byte order.
         *
         * After the two-byte version indicator, the file has three parts:
         *  * the header (in version 4 only),
         *  * the default principal name,
         *  * and a sequence of credentials
         *
         * header ::=
         *     It begins with a 16-bit integer giving the length of the entire header, followed by a sequence of fields.
         *     Each field consists of a 16-bit tag, a 16-bit length, and a value of the given length.
         *
         * principal ::=
         *     name type (32 bits) [omitted in version 1]
         *     count of components (32 bits) [includes realm in version 1]
         *     realm (data)
         *     component1 (data)
         *     component2 (data)
         *     ...
         *
         * data ::=
         *     length (32 bits)
         *     value (length bytes)
         *
         * credential ::=
         *     client (principal)
         *     server (principal)
         *     keyblock (keyblock)
         *     authtime (32 bits)
         *     starttime (32 bits)
         *     endtime (32 bits)
         *     renew_till (32 bits)
         *     is_skey (1 byte, 0 or 1)
         *     ticket_flags (32 bits)
         *     addresses (addresses)
         *     authdata (authdata)
         *     ticket (data)
         *     second_ticket (data)
         *
         * keyblock ::=
         *     enctype (16 bits) [repeated twice in version 3]
         *     data
         *
         * addresses ::=
         *     count (32 bits)
         *     address1
         *     address2
         *     ...
         *
         * address ::=
         *     addrtype (16 bits)
         *     data
         *
         * authdata ::=
         *     count (32 bits)
         *     authdata1
         *     authdata2
         *     ...
         *
         * authdata ::=
         *     ad_type (16 bits)
         *     data
         */

        public int Version { get; set; } = ExpectedVersion4;

        public IDictionary<Krb5CredentialCacheTag, ReadOnlyMemory<byte>> Header { get; } = new Dictionary<Krb5CredentialCacheTag, ReadOnlyMemory<byte>>();

        public PrincipalName DefaultPrincipalName { get; set; }

        public ICollection<Krb5Credential> Credentials { get; } = new List<Krb5Credential>();

        public bool FastAvailable { get; set; }

        public string PreAuthConfiguration { get; set; }

        public PaDataType PreAuthType { get; set; }

        public string ProxyImpersonator { get; set; }

        public void Clear()
        {
            this.Credentials.Clear();
        }

        internal void Read(byte[] cache)
        {
            this.Credentials.Clear();
            this.Header.Clear();

            using (var buffer = new NdrBuffer(cache, align: false))
            {
                var magic = buffer.Read(1)[0];

                if (magic != Magic)
                {
                    throw new InvalidOperationException($"Unknown file format. Expected 0x{Magic}; Actual 0x{magic}.");
                }

                this.Version = buffer.Read(1)[0];

                if (this.Version != ExpectedVersion3 && this.Version != ExpectedVersion4)
                {
                    throw new InvalidOperationException(
                        $"Unknown file format version. Expected 0x{ExpectedVersion4} or 0x{ExpectedVersion3}; Actual 0x{this.Version}."
                    );
                }

                try
                {
                    if (this.Version >= ExpectedVersion4)
                    {
                        this.ReadHeader(buffer);
                    }

                    this.DefaultPrincipalName = ReadPrincipal(buffer);

                    this.ReadCredentials(buffer);
                }
                catch (ArgumentException)
                {
                    throw new InvalidDataException($"The cache file appears corrupt around byte offset {buffer.Offset}");
                }
            }
        }

        internal byte[] Serialize()
        {
            if (this.Version < ExpectedVersion3)
            {
                this.Version = ExpectedVersion4;
            }

            using (var buffer = new NdrBuffer(align: false))
            {
                buffer.WriteByte(Magic);
                buffer.WriteByte((byte)this.Version);

                if (this.Version >= ExpectedVersion4)
                {
                    this.WriteHeader(buffer);
                }

                WritePrincipal(this.DefaultPrincipalName, buffer);

                this.WriteCredentials(buffer);

                return buffer.ToMemory(0).ToArray();
            }
        }

        internal void Add(TicketCacheEntry entry)
        {
            var existing = this.FindCredential(entry.Key);

            if (existing != null)
            {
                this.Credentials.Remove(existing);
            }

            if (entry.Value is KerberosClientCacheEntry entryValue)
            {
                if (entryValue.KdcResponse is KrbAsRep asRep && !this.Credentials.Any())
                {
                    this.DefaultPrincipalName = FromResponse(asRep, asRep.CName);
                }

                this.Credentials.Add(new Krb5Credential
                {
                    Ticket = entryValue.KdcResponse.Ticket.EncodeApplication(),
                    KeyBlock = new KeyValuePair<EncryptionType, ReadOnlyMemory<byte>>(entryValue.SessionKey.EType, entryValue.SessionKey.KeyValue),
                    Client = FromResponse(entryValue.KdcResponse, entryValue.KdcResponse.CName),
                    Server = FromResponse(entryValue.KdcResponse, entryValue.KdcResponse.Ticket.SName),
                    AuthData = new List<KrbAuthorizationData>(),
                    EndTime = entry.Expires,
                    RenewTill = entry.RenewUntil ?? DateTimeOffset.MinValue,
                    Addresses = new List<KrbHostAddress>(),
                    SecondTicket = Array.Empty<byte>(),
                    Flags = entryValue.Flags
                });
            }
        }

        private static PrincipalName FromResponse(KrbKdcRep asRep, KrbPrincipalName name)
        {
            return new PrincipalName(asRep.CName.Type, asRep.CRealm, name.Name);
        }

        internal IEnumerable<object> GetAllItems()
        {
            return this.Credentials.Select(c => CredToCacheEntry(c));
        }

        internal object GetCacheItem(string key)
        {
            Krb5Credential cred = this.FindCredential(key);

            if (cred is null)
            {
                return null;
            }

            return CredToCacheEntry(cred);
        }

        private static object CredToCacheEntry(Krb5Credential cred)
        {
            return new KerberosClientCacheEntry
            {
                KdcResponse = new KrbTgsRep
                {
                    Ticket = KrbTicket.DecodeApplication(cred.Ticket),
                    CName = KrbPrincipalName.FromString(cred.Client.FullyQualifiedName, cred.Client.Type),
                    CRealm = cred.Client.Realm,
                    EncPart = new KrbEncryptedData { }
                },
                SessionKey = new KrbEncryptionKey
                {
                    EType = cred.KeyBlock.Key,
                    KeyValue = cred.KeyBlock.Value
                },
                Flags = cred.Flags,
                SName = KrbPrincipalName.FromString(cred.Server.FullyQualifiedName),
                AuthTime = cred.AuthTime,
                StartTime = cred.StartTime,
                EndTime = cred.EndTime,
                RenewTill = cred.RenewTill <= DateTimeOffset.MinValue ? null : cred.RenewTill
            };
        }

        private Krb5Credential FindCredential(string key)
        {
            var lookupPrincipal = KrbPrincipalName.FromString(key);

            return this.Credentials.FirstOrDefault(c => c.Server.Equals(lookupPrincipal));
        }

        internal bool Contains(TicketCacheEntry entry)
        {
            Krb5Credential cred = this.FindCredential(entry.Key);

            return cred != null;
        }

        private void WriteCredentials(NdrBuffer buffer)
        {
            foreach (var cred in this.Credentials)
            {
                WriteCredential(cred, buffer, this.Version);
            }

            this.WriteConfiguration(buffer);
        }

        private static void WriteCredential(Krb5Credential cred, NdrBuffer buffer, int version)
        {
            WritePrincipal(cred.Client, buffer);
            WritePrincipal(cred.Server, buffer);
            WriteKeyBlock(cred.KeyBlock, buffer, version);
            WriteDateTimeOffset(cred.AuthTime, buffer);
            WriteDateTimeOffset(cred.StartTime, buffer);
            WriteDateTimeOffset(cred.EndTime, buffer);
            WriteDateTimeOffset(cred.RenewTill, buffer);
            buffer.WriteByte(cred.IsKey ? (byte)0x1 : (byte)0x0);
            buffer.WriteInt32BigEndian((int)cred.Flags);
            WriteAddresses(cred.Addresses, buffer);
            WriteAuthData(cred.AuthData, buffer);
            WriteData(cred.Ticket, buffer);
            WriteData(cred.SecondTicket, buffer);
        }

        private void ReadCredentials(NdrBuffer buffer)
        {
            while (buffer.BytesAvailable > 0)
            {
                var cred = new Krb5Credential
                {
                    Client = ReadPrincipal(buffer),
                    Server = ReadPrincipal(buffer),
                    KeyBlock = ReadKeyBlock(buffer, this.Version),
                    AuthTime = ReadDateTimeOffset(buffer),
                    StartTime = ReadDateTimeOffset(buffer),
                    EndTime = ReadDateTimeOffset(buffer),
                    RenewTill = ReadDateTimeOffset(buffer),
                    IsKey = buffer.ReadByteLittleEndian() != 0,
                    Flags = (TicketFlags)buffer.ReadInt32BigEndian(),
                    Addresses = ReadAddresses(buffer),
                    AuthData = ReadAuthData(buffer),
                    Ticket = ReadData(buffer).value,
                    SecondTicket = ReadData(buffer).value
                };

                if ("X-CACHECONF:".Equals(cred.Server.Realm, StringComparison.OrdinalIgnoreCase))
                {
                    this.ParseConfiguration(cred);
                }
                else
                {
                    this.Credentials.Add(cred);
                }
            }
        }

        private void WriteConfiguration(NdrBuffer buffer)
        {
            const string confData = "krb5_ccache_conf_data";
            const string confRealm = "X-CACHECONF:";

            var client = this.DefaultPrincipalName;

            if (this.FastAvailable)
            {
                WriteCredential(
                    new Krb5Credential
                    {
                        Ticket = Encoding.UTF8.GetBytes("yes"),
                        Client = client,
                        Server = new PrincipalName(PrincipalNameType.NT_UNKNOWN, confRealm, new[] { confData, "fast_avail", $"krbtgt/{client.Realm}@{client.Realm}" })
                    },
                    buffer,
                    this.Version
                );
            }

            WriteCredential(
                new Krb5Credential
                {
                    Ticket = new[] { (byte)((int)this.PreAuthType).ToString(CultureInfo.InvariantCulture)[0] },
                    Client = client,
                    Server = new PrincipalName(PrincipalNameType.NT_UNKNOWN, confRealm, new[] { confData, "pa_type", $"krbtgt/{client.Realm}@{client.Realm}" })
                },
                buffer,
                this.Version
            );
        }

        private void ParseConfiguration(Krb5Credential cred)
        {
            if (cred.Server.Name.Length < 2)
            {
                return;
            }

            if (!"krb5_ccache_conf_data".Equals(cred.Server.Name[0], StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            switch (cred.Server.Name[1])
            {
                case "fast_avail":
                    this.FastAvailable = "yes".Equals(Encoding.UTF8.GetString(cred.Ticket.ToArray()), StringComparison.OrdinalIgnoreCase);
                    break;
                case "pa_config_data":
                    this.PreAuthConfiguration = Encoding.UTF8.GetString(cred.Ticket.ToArray());
                    break;
                case "pa_type":
                    this.PreAuthType = (PaDataType)(int)char.GetNumericValue((char)cred.Ticket.Span[0]);
                    break;
                case "proxy_impersonator":
                    this.ProxyImpersonator = Encoding.UTF8.GetString(cred.Ticket.ToArray());
                    break;
                case "refresh_time":
                    break;
            }
        }

        private static void WriteAuthData(IEnumerable<KrbAuthorizationData> authData, NdrBuffer buffer)
        {
            if (authData == null)
            {
                authData = Array.Empty<KrbAuthorizationData>();
            }

            buffer.WriteInt32BigEndian(authData.Count());

            foreach (var az in authData)
            {
                buffer.WriteInt16BigEndian((short)az.Type);
                WriteData(az.Data, buffer);
            }
        }

        private static IEnumerable<KrbAuthorizationData> ReadAuthData(NdrBuffer buffer)
        {
            var count = buffer.ReadInt32BigEndian();

            var list = new List<KrbAuthorizationData>();

            for (var i = 0; i < count; i++)
            {
                var adType = (AuthorizationDataType)buffer.ReadInt16BigEndian();
                var data = ReadData(buffer);

                list.Add(new KrbAuthorizationData { Type = adType, Data = data.value });
            }

            return list;
        }

        private static void WriteAddresses(IEnumerable<KrbHostAddress> addresses, NdrBuffer buffer)
        {
            if (addresses == null)
            {
                addresses = Array.Empty<KrbHostAddress>();
            }

            buffer.WriteInt32BigEndian(addresses.Count());

            foreach (var addr in addresses)
            {
                buffer.WriteInt16BigEndian((short)addr.AddressType);
                WriteData(addr.Address, buffer);
            }
        }

        private static IEnumerable<KrbHostAddress> ReadAddresses(NdrBuffer buffer)
        {
            var count = buffer.ReadInt32BigEndian();

            var list = new List<KrbHostAddress>();

            for (var i = 0; i < count; i++)
            {
                var addrType = (AddressType)buffer.ReadInt16BigEndian();
                var data = ReadData(buffer);

                list.Add(new KrbHostAddress { AddressType = addrType, Address = data.value });
            }

            return list;
        }

        private static void WriteDateTimeOffset(DateTimeOffset dt, NdrBuffer buffer)
        {
            var epoch = GetEpoch(dt);

            buffer.WriteInt32BigEndian(epoch);
        }

        private static DateTimeOffset ReadDateTimeOffset(NdrBuffer buffer)
        {
            var time = buffer.ReadInt32BigEndian();

            return DateTimeOffset.FromUnixTimeSeconds(time);
        }

        private static void WriteKeyBlock(KeyValuePair<EncryptionType, ReadOnlyMemory<byte>> kv, NdrBuffer buffer, int version)
        {
            buffer.WriteInt16BigEndian((short)kv.Key);

            if (version == ExpectedVersion3)
            {
                buffer.WriteInt16BigEndian((short)kv.Key);
            }

            WriteData(kv.Value, buffer);
        }

        private static KeyValuePair<EncryptionType, ReadOnlyMemory<byte>> ReadKeyBlock(NdrBuffer buffer, int version)
        {
            var encType = (EncryptionType)buffer.ReadInt16BigEndian();

            if (version == ExpectedVersion3)
            {
                // v3 repeats
                _ = buffer.ReadInt16BigEndian();
            }

            var (_, value) = ReadData(buffer);

            return new KeyValuePair<EncryptionType, ReadOnlyMemory<byte>>(encType, value);
        }

        private static void WritePrincipal(PrincipalName principal, NdrBuffer buffer)
        {
            buffer.WriteInt32BigEndian((int)principal.Type);
            buffer.WriteInt32BigEndian(principal.Name.Length);

            WriteData(Encoding.UTF8.GetBytes(principal.Realm), buffer);

            foreach (var name in principal.Name)
            {
                WriteData(Encoding.UTF8.GetBytes(name), buffer);
            }
        }

        private static PrincipalName ReadPrincipal(NdrBuffer buffer)
        {
            var type = (PrincipalNameType)buffer.ReadInt32BigEndian();
            var count = buffer.ReadInt32BigEndian();

            var (length, value) = ReadData(buffer);

            string realm = string.Empty;

            if (length > 0)
            {
                realm = Encoding.UTF8.GetString(value.ToArray());
            }

            var components = new List<string>();

            for (var i = 0; i < count; i++)
            {
                var component = ReadData(buffer);

                components.Add(Encoding.UTF8.GetString(component.value.ToArray()));
            }

            return new PrincipalName(type, realm, components);
        }

        private static void WriteData(ReadOnlyMemory<byte> data, NdrBuffer buffer)
        {
            buffer.WriteInt32BigEndian(data.Length);
            buffer.WriteMemory(data);
        }

        private static (int length, ReadOnlyMemory<byte> value) ReadData(NdrBuffer buffer)
        {
            /*
            * data ::=
            *     length (32 bits)
            *     value (length bytes)
             */

            var length = buffer.ReadInt32BigEndian();
            var value = buffer.ReadMemory(length);

            return (length, value);
        }

        private void WriteHeader(NdrBuffer buffer)
        {
            using (var headerBuffer = new NdrBuffer(align: false))
            {
                foreach (var kv in this.Header)
                {
                    headerBuffer.WriteInt16BigEndian((short)kv.Key);
                    headerBuffer.WriteInt16BigEndian((short)kv.Value.Length);
                    headerBuffer.WriteMemory(kv.Value);
                }

                var header = headerBuffer.ToMemory(0);

                buffer.WriteInt16BigEndian((short)header.Length);
                buffer.WriteMemory(header);
            }
        }

        private void ReadHeader(NdrBuffer buffer)
        {
            var headerLength = buffer.ReadInt16BigEndian();

            while (headerLength > 0)
            {
                var tag = (Krb5CredentialCacheTag)buffer.ReadInt16BigEndian();
                headerLength -= sizeof(short);

                var length = buffer.ReadInt16BigEndian();
                headerLength -= sizeof(short);

                var value = buffer.ReadMemory(length);
                headerLength -= length;

                this.Header[tag] = value;
            }
        }

        private static int GetEpoch(DateTimeOffset dt) => dt == DateTimeOffset.MinValue ? 0 : (int)dt.ToUnixTimeSeconds();

        [DebuggerDisplay("{Client} {Server}")]
        public class Krb5Credential
        {
            public PrincipalName Client { get; set; }

            public PrincipalName Server { get; set; }

            public KeyValuePair<EncryptionType, ReadOnlyMemory<byte>> KeyBlock { get; set; }

            public DateTimeOffset AuthTime { get; set; }

            public DateTimeOffset StartTime { get; set; }

            public DateTimeOffset EndTime { get; set; }

            public DateTimeOffset RenewTill { get; set; }

            public bool IsKey { get; set; }

            public TicketFlags Flags { get; set; }

            public IEnumerable<KrbHostAddress> Addresses { get; set; }

            public IEnumerable<KrbAuthorizationData> AuthData { get; set; }

            public ReadOnlyMemory<byte> Ticket { get; set; }

            public ReadOnlyMemory<byte> SecondTicket { get; set; }
        }
    }

    public enum Krb5CredentialCacheTag : short
    {
        KdcClientOffset = 1
    }
}
