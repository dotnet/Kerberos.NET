// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Crypto
{
    public class KeyEntry
    {
        public KeyEntry(KerberosKey key)
        {
            this.Key = key;
            this.Principal = key?.PrincipalName;
            this.EncryptionType = key?.EncryptionType;
            this.Version = key?.Version ?? 5;
            this.Timestamp = DateTimeOffset.MinValue;
        }

        public KeyEntry(BinaryReader reader, int version)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            var length = ReadInt32(reader);

            if (length <= 0)
            {
                length *= -1;

                reader.BaseStream.Seek(length, SeekOrigin.Current);
                return;
            }

            this.Length = length;

            var startPosition = reader.BaseStream.Position;

            var bytesAvailable = reader.BytesAvailable();

            if (this.Length > bytesAvailable)
            {
                throw new InvalidDataException(
                    $"Cannot read KeyEntry because expected length {this.Length} is greater than available bytes to read {bytesAvailable}."
                );
            }

            this.Principal = ReadPrincipal(reader, version);

            this.Timestamp = ReadDateTime(reader);

            this.Version = reader.ReadByte();

            this.Key = this.ReadKey(reader);

            var endPosition = reader.BaseStream.Position;

            var bytesConsumedInEntry = endPosition - startPosition;

            if (this.Length - bytesConsumedInEntry >= 4)
            {
                var newVersion = ReadInt32(reader);
                if (newVersion != 0)
                {
                    this.Version = newVersion;
                }

                bytesConsumedInEntry += 4;
            }

            if (bytesConsumedInEntry < this.Length)
            {
                reader.BaseStream.Seek(this.Length - bytesConsumedInEntry, SeekOrigin.Current);
            }
        }

        public void WriteKeyEntry(BinaryWriter finalWriter)
        {
            if (finalWriter == null)
            {
                throw new ArgumentNullException(nameof(finalWriter));
            }

            var buffer = new MemoryStream();

            using (var writer = new BinaryWriter(buffer))
            {
                var key = this;

                if (key.Key != null)
                {
                    WritePrincipal(writer, key.Principal);
                    WriteDateTime(writer, key.Timestamp);
                    writer.Write(new byte[] { (byte)key.Version });
                    WriteKey(writer, key.Key);

                    WriteInt32(finalWriter, (int)writer.BaseStream.Length);
                }
                else
                {
                    const int placeholderLength = 16;

                    writer.Write(new byte[placeholderLength]);
                    WriteInt32(finalWriter, -placeholderLength);
                }

                finalWriter.Write(buffer.ToArray());
            }
        }

        public PrincipalName Principal { get; private set; }

        public DateTimeOffset Timestamp { get; private set; }

        public KerberosKey Key { get; private set; }

        public EncryptionType? EncryptionType { get; private set; }

        public int Version { get; private set; } = 5;

        public int Length { get; private set; }

        private KerberosKey ReadKey(BinaryReader reader)
        {
            this.EncryptionType = (EncryptionType)ReadInt16(reader);

            var key = ReadBytes(reader);

            return new KerberosKey(key, etype: this.EncryptionType ?? Crypto.EncryptionType.NULL);
        }

        private static DateTimeOffset ReadDateTime(BinaryReader reader)
        {
            var time = ReadInt32(reader);

            var ts = TimeSpan.FromSeconds(time);

            return UNIX_EPOCH_BASE.Add(ts);
        }

        private static string ReadString(BinaryReader reader)
        {
            return Encoding.UTF8.GetString(ReadBytes(reader));
        }

        private static byte[] ReadBytes(BinaryReader reader)
        {
            var length = ReadInt16(reader);

            return reader.ReadBytes(length);
        }

        private static int ReadInt32(BinaryReader reader)
        {
            var bytes = reader.ReadBytes(4);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            return BitConverter.ToInt32(bytes, 0);
        }

        private static short ReadInt16(BinaryReader reader)
        {
            var bytes = reader.ReadBytes(2);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            return BitConverter.ToInt16(bytes, 0);
        }

        private static PrincipalName ReadPrincipal(BinaryReader reader, int version)
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
            var components = principal.Name.SelectMany(s => s.Split('/'));

            WriteInt16(writer, (short)components.Count());

            WriteString(writer, principal.Realm);

            foreach (var component in components)
            {
                WriteString(writer, component);
            }

            WriteInt32(writer, (int)principal.Type);
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

        private static readonly DateTimeOffset UNIX_EPOCH_BASE = new(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

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

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            writer.Write(bytes);
        }

        private static void WriteInt32(BinaryWriter writer, int val)
        {
            var bytes = BitConverter.GetBytes(val);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            writer.Write(bytes);
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(
                this.EncryptionType ?? Crypto.EncryptionType.NULL,
                this.Key,
                this.Principal,
                this.Timestamp,
                this.Version
            );
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
            return $"V{this.Version} {this.EncryptionType} {this.Principal?.Realm}".Trim();
        }
    }
}
