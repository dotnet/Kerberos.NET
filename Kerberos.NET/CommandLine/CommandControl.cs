// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;

namespace Kerberos.NET.CommandLine
{
    public class CommandControl
    {
        public TextWriter Writer { get; set; }

        public TextReader Reader { get; set; }

        public Action Clear { get; set; }

        public Func<ConsoleKeyInfo> ReadKey { get; set; }
    }
}
