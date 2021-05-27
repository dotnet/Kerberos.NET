// -----------------------------------------------------------------------
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    public class BaseCryptoTest
    {
        protected static byte[] HexToByte(string hex)
        {
            hex = hex?.Replace(" ", string.Empty).Replace("0x", string.Empty).Replace(",", string.Empty);

            return Enumerable.Range(0, hex.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                     .ToArray();
        }

        protected static void AssertArrayEquals(ReadOnlyMemory<byte> expectedBytes, ReadOnlyMemory<byte> actualBytes)
        {
            Assert.IsTrue(expectedBytes.Span.SequenceEqual(actualBytes.Span));
        }

        protected static ReadOnlyMemory<byte> UnicodeStringToUtf8(string str)
        {
            return UnicodeBytesToUtf8(Encoding.Unicode.GetBytes(str));
        }

        protected static ReadOnlyMemory<byte> UnicodeBytesToUtf8(byte[] str)
        {
            return Encoding.Convert(Encoding.Unicode, Encoding.UTF8, str, 0, str?.Length ?? 0);
        }
    }
}