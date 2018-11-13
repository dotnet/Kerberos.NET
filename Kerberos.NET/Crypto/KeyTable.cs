using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Crypto
{
    [DebuggerDisplay("Kerbers V{KerberosVersion} File V{FileVersion} Count = {Entries.Count}")]
    public class KeyTable
    {
        public KeyTable(params KerberosKey[] keys)
        {
            foreach (var key in keys)
            {
                Entries.Add(new KeyEntry(key));
            }
        }

        public KeyTable(byte[] data)
            : this(new MemoryStream(data))
        {

        }

        public KeyTable(Stream stream)
        {
            var reader = new BinaryReader(stream);

            KerberosVersion = reader.ReadByte();
            FileVersion = reader.ReadByte();

            ProcessEntries(reader);
        }

        private void ProcessEntries(BinaryReader reader)
        {
            while (reader.BytesAvailable() > 0)
            {
                Entries.Add(new KeyEntry(reader, KerberosVersion));
            }
        }

        public int KerberosVersion { get; private set; } = 5;

        public int FileVersion { get; private set; } = 2;

        private ICollection<KeyEntry> entries;

        public ICollection<KeyEntry> Entries { get { return entries ?? (entries = new List<KeyEntry>()); } }

        public KerberosKey GetKey(KrbApReq token)
        {
            var type = token.Ticket.EncPart.EType;
            var sname = token.Ticket.SName;

            // Match on type (e.g. RC4_HMAC_NT) and name (Realm + Name)
            var entry = Entries.FirstOrDefault(e => e.EncryptionType == type && sname.Matches(e.Principal));

            // Fall back to first entry with matching type (RC4_HMAC_NT)
            if (entry == null)
            {
                entry = Entries.FirstOrDefault(e => e.EncryptionType == type);
            }

            // Fall back to first entry
            if (entry == null)
            {
                entry = Entries.FirstOrDefault();
            }

            return entry?.Key;
        }
    }

    [DebuggerDisplay("{Version} {EncryptionType} {Principal?.Realm}")]
    public class KeyEntry
    {
        public KeyEntry(BinaryReader reader, int version)
        {
            Length = ReadInt32(reader);

            var startPosition = reader.BaseStream.Position;

            var bytesAvailable = reader.BytesAvailable();

            if (Length > bytesAvailable)
            {
                throw new InvalidDataException(
                    $"Cannot read KeyEntry because expected length {Length} is greater than available bytes to read {bytesAvailable}."
                );
            }

            Principal = ReadPrincipal(reader, version);

            Timestamp = ReadDateTime(reader);

            Version = reader.ReadByte();

            Key = ReadKey(reader);

            var endPosition = reader.BaseStream.Position;

            var bytesConsumedInEntry = endPosition - startPosition;

            if (Length - bytesConsumedInEntry >= 4)
            {
                var newVersion = ReadInt32(reader);
                if (newVersion != 0)
                {
                    Version = newVersion;
                }

                bytesConsumedInEntry += 4;
            }

            if (bytesConsumedInEntry < Length)
            {
                reader.BaseStream.Seek(Length - bytesConsumedInEntry, SeekOrigin.Current);
            }
        }

        public KeyEntry(KerberosKey key)
        {
            Key = key;
            Principal = key.PrincipalName;
        }

        public PrincipalName Principal { get; private set; }

        public DateTimeOffset Timestamp { get; private set; }

        public KerberosKey Key { get; private set; }

        public EncryptionType? EncryptionType { get; private set; }

        public int Version { get; private set; }

        public int Length { get; private set; }

        private PrincipalName ReadPrincipal(BinaryReader reader, int version)
        {
            var componentCount = ReadInt16(reader);

            if (version == 1)
            {
                componentCount -= 1;
            }

            var realm = ReadString(reader);

            var names = new List<string>();

            var sb = new StringBuilder();

            for (var i = 0; i < componentCount; i++)
            {
                sb.Append(ReadString(reader));

                if (i < componentCount - 1)
                {
                    sb.Append("/");
                }
            }

            names.Add(sb.ToString());

            var nameType = (PrincipalNameType)ReadInt32(reader);

            return new PrincipalName(nameType, realm, names);
        }

        private KerberosKey ReadKey(BinaryReader reader)
        {
            EncryptionType = (EncryptionType)ReadInt16(reader);

            var key = ReadBytes(reader);

            return new KerberosKey(key);
        }

        private DateTimeOffset ReadDateTime(BinaryReader reader)
        {
            var time = ReadInt32(reader);

            var ts = TimeSpan.FromSeconds(time);

            return DateTimeOffset.MinValue.Add(ts);
        }

        private string ReadString(BinaryReader reader)
        {
            return Encoding.UTF8.GetString(ReadBytes(reader));
        }

        private byte[] ReadBytes(BinaryReader reader)
        {
            var length = ReadInt16(reader);

            return reader.ReadBytes(length);
        }

        private static int ReadInt32(BinaryReader reader)
        {
            var bytes = reader.ReadBytes(4);

            Array.Reverse(bytes);

            return BitConverter.ToInt32(bytes, 0);
        }

        private static short ReadInt16(BinaryReader reader)
        {
            var bytes = reader.ReadBytes(2);

            Array.Reverse(bytes);

            return BitConverter.ToInt16(bytes, 0);
        }
    }
}