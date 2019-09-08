using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Crypto
{
    [DebuggerDisplay("Kerberos V{KerberosVersion} File V{FileVersion} Count = {Entries.Count}")]
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

        public void Write(BinaryWriter writer)
        {
            writer.Write((byte)KerberosVersion);
            writer.Write((byte)FileVersion);

            foreach (var entry in Entries)
            {
                entry.WriteKeyEntry(writer);
            }
        }

        public int KerberosVersion { get; private set; } = 5;

        public int FileVersion { get; private set; } = 2;

        private ICollection<KeyEntry> entries;

        public ICollection<KeyEntry> Entries { get { return entries ?? (entries = new List<KeyEntry>()); } }

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

            return GetKey(etype, sname);
        }

        public KerberosKey GetKey(EncryptionType type, KrbPrincipalName sname)
        {
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

    public class KeyEntry
    {
        public KeyEntry(KerberosKey key)
        {
            this.Key = key;
            this.Principal = key.PrincipalName;
            this.EncryptionType = key.EncryptionType;
            this.Timestamp = DateTimeOffset.UtcNow;
        }

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

        public void WriteKeyEntry(BinaryWriter finalWriter)
        {
            var buffer = new MemoryStream();
            var writer = new BinaryWriter(buffer);

            var key = this;

            WritePrincipal(writer, key.Principal);
            WriteDateTime(writer, key.Timestamp);
            writer.Write(new byte[] { (byte)key.Version });
            WriteKey(writer, key.Key);

            WriteInt32(finalWriter, (int)writer.BaseStream.Length);

            finalWriter.Write(buffer.ToArray());
        }

        public PrincipalName Principal { get; private set; }

        public DateTimeOffset Timestamp { get; private set; }

        public KerberosKey Key { get; private set; }

        public EncryptionType? EncryptionType { get; private set; }

        public int Version { get; private set; } = 5;

        public int Length { get; private set; }

        private KerberosKey ReadKey(BinaryReader reader)
        {
            EncryptionType = (EncryptionType)ReadInt16(reader);

            var key = ReadBytes(reader);

            return new KerberosKey(key, etype: EncryptionType ?? Crypto.EncryptionType.NULL);
        }

        private DateTimeOffset ReadDateTime(BinaryReader reader)
        {
            var time = ReadInt32(reader);

            var ts = TimeSpan.FromSeconds(time);

            return UNIX_EPOCH_BASE.Add(ts);
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

        private static void WritePrincipal(BinaryWriter writer, PrincipalName principal)
        {
            var components = principal.Names.SelectMany(s => s.Split('/'));

            WriteInt16(writer, (short)components.Count());

            WriteString(writer, principal.Realm);

            foreach (var component in components)
            {
                WriteString(writer, component);
            }

            WriteInt32(writer, (int)principal.NameType);
        }

        private static void WriteKey(BinaryWriter writer, KerberosKey key)
        {
            WriteInt16(writer, (short)key.EncryptionType);

            WriteBytes(writer, key.GetKey().ToArray());
        }

        private static void WriteString(BinaryWriter writer, string val)
        {
            var bytes = Encoding.UTF8.GetBytes(val);

            WriteBytes(writer, bytes);
        }

        private static readonly DateTimeOffset UNIX_EPOCH_BASE = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

        private static void WriteDateTime(BinaryWriter writer, DateTimeOffset dt)
        {
            WriteInt32(writer, GetEpoch(dt));
        }

        private static void WriteBytes(BinaryWriter writer, byte[] val)
        {
            WriteInt16(writer, (short)val.Length);

            writer.Write(val);
        }

        private static void WriteInt16(BinaryWriter writer, short val)
        {
            var bytes = BitConverter.GetBytes(val);

            Array.Reverse(bytes);

            writer.Write(bytes);
        }

        private static void WriteInt32(BinaryWriter writer, int val)
        {
            var bytes = BitConverter.GetBytes(val);

            Array.Reverse(bytes);

            writer.Write(bytes);
        }

        public override int GetHashCode()
        {
            return (this.EncryptionType ?? Crypto.EncryptionType.NULL).GetHashCode() ^
                    Key.GetHashCode() ^
                    Principal.GetHashCode() ^
                    Timestamp.GetHashCode() ^
                    Version.GetHashCode();
        }

        public override bool Equals(object obj)
        {
            if (!(obj is KeyEntry key))
            {
                return base.Equals(obj);
            }

            return key.EncryptionType == this.EncryptionType &&
                   key.Key.Equals(this.Key) &&
                   key.Principal.Equals(this.Principal) &&
                   GetEpoch(key.Timestamp) == GetEpoch(this.Timestamp) &&
                   key.Version == this.Version;
        }

        private static int GetEpoch(DateTimeOffset dt)
        {
            TimeSpan ts;

            if (dt == DateTimeOffset.MinValue)
            {
                ts = TimeSpan.Zero;
            }
            else
            {
                ts = dt.Subtract(UNIX_EPOCH_BASE);
            }

            return (int)ts.TotalSeconds;
        }

        public override string ToString()
        {
            return $"V{Version} {EncryptionType} {Principal?.Realm}";
        }
    }
}