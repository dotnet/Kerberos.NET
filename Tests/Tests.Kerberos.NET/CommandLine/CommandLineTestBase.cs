// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;

namespace Tests.Kerberos.NET
{
    public class CommandLineTestBase
    {
        protected static ConsoleKey ConvertKey(char chr)
        {
            if (chr == '\r' || chr == '\n')
            {
                return ConsoleKey.Enter;
            }

            return 0;
        }

        protected static void TryCleanupTmp(string tmpCacheFile)
        {
            for (var i = 0; i < 10; i++)
            {
                try
                {
                    File.Delete(tmpCacheFile);
                    break;
                }
                catch
                {
                }
            }
        }

        protected private static ConsoleKeyInfo ReadKey(CommandLineAutoReader reader)
        {
            var chr = reader.ReadKey();

            ConsoleKey key = ConvertKey(chr);

            return new ConsoleKeyInfo(chr, key, false, false, false);
        }
    }
}
