// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class AuthScheme
    {
        [KerberosIgnore]
        public uint AuthSchemeArrayOffset { get; }

        [KerberosIgnore]
        public ushort AuthSchemeCount { get; }

        public IEnumerable<Guid> Schemes { get; }

        public AuthScheme(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            this.AuthSchemeArrayOffset = reader.ReadUInt32();
            this.AuthSchemeCount = reader.ReadUInt16();

            var schemes = new List<Guid>();

            var offset = reader.BaseStream.Position;

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            reader.BaseStream.Seek(this.AuthSchemeArrayOffset, SeekOrigin.Begin);

            for (var i = 0; i < this.AuthSchemeCount; i++)
            {
                var scheme = reader.ReadBytes(16);

                schemes.Add(new Guid(scheme));
            }

            this.Schemes = schemes;

            reader.BaseStream.Seek(offset, SeekOrigin.Begin);
        }
    }
}