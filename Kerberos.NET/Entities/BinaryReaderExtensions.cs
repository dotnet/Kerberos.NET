// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;

namespace Kerberos.NET.Entities
{
    public static class BinaryReaderExtensions
    {
        public static long BytesAvailable(this BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            return reader.BaseStream.Length - reader.BaseStream.Position;
        }
    }
}