﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public static class Hex
    {
        public static void Debug(byte[] v) => System.Diagnostics.Debug.WriteLine(DumpHex(v));
        public static void Debug(ReadOnlyMemory<byte> v) => System.Diagnostics.Debug.WriteLine(DumpHex(v));

        public static string DumpHex(this ReadOnlyMemory<byte> bytes, int bytesPerLine = 16)
        {
            return HexDump(bytes.ToArray(), bytesPerLine);
        }

        public static void DumpHex(this ReadOnlyMemory<byte> bytes, Action<string, int> writeLine, int bytesPerLine = 16)
        {
            var lines = HexDump(bytes.Span, bytesPerLine).Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

            for (var i = 0; i < lines.Length; i++)
            {
                writeLine(lines[i], i);
            }
        }

        public static unsafe string DumpHex(this IntPtr pThing, uint length)
        {
            var pBytes = (byte*)pThing;

            return HexDump(pBytes, length);
        }

        private static unsafe string HexDump(byte* bytes, uint length, int bytesPerLine = 16)
        {
            var lengthInt = (int)length;

            using (var pool = CryptoPool.Rent<byte>(lengthInt))
            {
                var managedBytes = pool.Memory.Slice(0, lengthInt);

                var span = new Span<byte>(bytes, lengthInt);

                span.CopyTo(managedBytes.Span);

                return HexDump(managedBytes.Span, bytesPerLine);
            }
        }

        public static string HexDump(this byte[] bytes, int bytesPerLine = 16)
        {
            return HexDump((ReadOnlySpan<byte>)bytes, bytesPerLine);
        }

        public static string HexDump(this ReadOnlySpan<byte> bytes, int bytesPerLine = 16)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            var sb = new StringBuilder();

            for (int line = 0; line < bytes.Length; line += bytesPerLine)
            {
                int bytesToRead = bytes.Length - line;

                var lineBytes = bytes.Slice(line, bytesToRead > bytesPerLine ? bytesPerLine : bytesToRead);

                sb.AppendFormat(CultureInfo.InvariantCulture, "{0:x8} ", line);

                for (var i = 0; i < lineBytes.Length; i++)
                {
                    var b = lineBytes[i];

                    sb.Append(HEX_INDEX[b]);

                    sb.Append(" ");
                }

                var padding = lineBytes.Length - bytesPerLine;

                if (padding > 0)
                {
                    for (var i = 0; i < padding; i++)
                    {
                        sb.Append("   ");
                    }
                }

                sb.Append(" ");

                for (var i = 0; i < lineBytes.Length; i++)
                {
                    var b = lineBytes[i];

                    sb.Append(char.IsControl((char)b) ? '.' : (char)b);
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }

        public static string Hexify(
            ReadOnlySpan<byte> hash,
            int lineLength = 0,
            bool spaces = false
        )
        {
            if (hash == null || hash.Length <= 0)
            {
                return null;
            }

            // It's considerably faster to just do a lookup and append
            // than to do something like BitConverter.ToString(byte[])

            int len = hash.Length * (spaces ? 3 : 2);

            var result = new StringBuilder(len);

            var lineCounter = 0;

            for (int i = 0; i < hash.Length; i++)
            {
                result.Append(HEX_INDEX[hash[i]]);

                if (spaces)
                {
                    result.Append(" ");
                }

                if (lineLength > 0 && ++lineCounter > lineLength)
                {
                    result.Append("\r\n");
                    lineCounter = 0;
                }
            }

            return result.ToString();
        }

        internal static readonly string[] HEX_INDEX = new string[]
        {
            "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
            "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
            "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
            "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
            "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
            "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
            "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
            "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
            "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db", "dc", "dd", "de", "df",
            "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
            "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff",
        };
    }
}
