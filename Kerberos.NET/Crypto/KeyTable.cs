// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Crypto
{
    [DebuggerDisplay("Kerberos V{KerberosVersion} File V{FileVersion} Count = {Entries.Count}")]
    public class KeyTable
    {
        public KeyTable(params KerberosKey[] keys)
        {
            foreach (var key in keys)
            {
                this.Entries.Add(new KeyEntry(key));
            }
        }

        public KeyTable(byte[] data)
            : this(new MemoryStream(data))
        {
        }

        public KeyTable(Stream stream)
        {
            using (var reader = new BinaryReader(stream))
            {
                this.KerberosVersion = reader.ReadByte();
                this.FileVersion = reader.ReadByte();

                this.ProcessEntries(reader);
            }
        }

        private void ProcessEntries(BinaryReader reader)
        {
            while (reader.BytesAvailable() > 0)
            {
                this.Entries.Add(new KeyEntry(reader, this.KerberosVersion));
            }
        }

        public void Write(BinaryWriter writer)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer));
            }

            writer.Write((byte)this.KerberosVersion);
            writer.Write((byte)this.FileVersion);

            foreach (var entry in this.Entries)
            {
                entry.WriteKeyEntry(writer);
            }
        }

        public int KerberosVersion { get; private set; } = 5;

        public int FileVersion { get; private set; } = 2;

        private ICollection<KeyEntry> entries;

        public ICollection<KeyEntry> Entries => this.entries ?? (this.entries = new List<KeyEntry>());

        public KerberosKey GetKey(ChecksumType type, KrbPrincipalName sname)
        {
            EncryptionType etype;

            switch (type)
            {
                case ChecksumType.HMAC_SHA1_96_AES128:
                    etype = EncryptionType.AES128_CTS_HMAC_SHA1_96;
                    break;
                case ChecksumType.HMAC_SHA1_96_AES256:
                    etype = EncryptionType.AES256_CTS_HMAC_SHA1_96;
                    break;

                case ChecksumType.KERB_CHECKSUM_HMAC_MD5:
                default:
                    etype = EncryptionType.RC4_HMAC_NT;
                    break;
            }

            return this.GetKey(etype, sname);
        }

        public KerberosKey GetKey(EncryptionType type, KrbPrincipalName sname)
        {
            // Match on type (e.g. RC4_HMAC_NT) and name (Realm + Name)

            var entry = this.Entries
                .Where(e => e.EncryptionType == type && sname.Matches(e.Principal))
                .OrderByDescending(x => x.Version)
                .FirstOrDefault();

            // Fall back to first entry with matching type (RC4_HMAC_NT)

            if (entry == null)
            {
                entry = this.Entries
                    .Where(e => e.EncryptionType == type)
                    .OrderByDescending(x => x.Version)
                    .FirstOrDefault();
            }

            // Fall back to first entry

            if (entry == null)
            {
                entry = this.Entries.FirstOrDefault();
            }

            return entry?.Key;
        }
    }
}
