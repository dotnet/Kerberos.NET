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
                var entry = new KeyEntry(reader, this.KerberosVersion);

                if (entry.Length > 0)
                {
                    this.Entries.Add(entry);
                }
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

        public ICollection<KeyEntry> Entries => this.entries ??= new List<KeyEntry>();

        private static EncryptionType EncryptionTypeForChecksumType(ChecksumType type)
            => type switch
            {
                ChecksumType.HMAC_SHA1_96_AES128 => EncryptionType.AES128_CTS_HMAC_SHA1_96,
                ChecksumType.HMAC_SHA1_96_AES256 => EncryptionType.AES256_CTS_HMAC_SHA1_96,
                ChecksumType.HMAC_SHA256_128_AES128 => EncryptionType.AES128_CTS_HMAC_SHA256_128,
                ChecksumType.HMAC_SHA384_192_AES256 => EncryptionType.AES256_CTS_HMAC_SHA384_192,
                _ => EncryptionType.RC4_HMAC_NT,
            };

        public IEnumerable<KerberosKey> GetKeys(ChecksumType type, KrbPrincipalName sname)
           => this.GetKeys(EncryptionTypeForChecksumType(type), sname);

        public KerberosKey GetKey(ChecksumType type, KrbPrincipalName sname)
            => this.GetKey(EncryptionTypeForChecksumType(type), sname);

        public IEnumerable<KerberosKey> GetKeys(EncryptionType type, KrbPrincipalName sname)
        {
            // try and find a matching entry

            var entries = this.Entries
                .Where(e => e.EncryptionType == type && (sname?.Matches(e.Principal) ?? true))
                .OrderByDescending(x => x.Version);

            if (!entries.Any())
            {
                // Fall back to first entry with matching type

                entries = this.Entries
                    .Where(e => e.EncryptionType == type)
                    .OrderByDescending(x => x.Version);
            }

            if (!entries.Any())
            {
                // fall back to first entry

                entries = this.Entries.OrderByDescending(x => x.Version);
            }

            return entries.Select(e => e.Key);
        }

        public KerberosKey GetKey(EncryptionType type, KrbPrincipalName sname)
        {
            // Match on type (e.g. RC4_HMAC_NT) and name (Realm + Name)

            var entry = this.Entries
                .Where(e => e.EncryptionType == type && (sname?.Matches(e.Principal) ?? true))
                .OrderByDescending(x => x.Version)
                .FirstOrDefault();

            // Fall back to first entry with matching type

            entry ??= this.Entries
                    .Where(e => e.EncryptionType == type)
                    .OrderByDescending(x => x.Version)
                    .FirstOrDefault();

            // Fall back to first entry

            entry ??= this.Entries.FirstOrDefault();

            return entry?.Key;
        }
    }
}
