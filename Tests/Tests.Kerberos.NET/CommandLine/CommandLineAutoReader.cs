// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;
using System.IO;

namespace Tests.Kerberos.NET
{
    public class CommandLineAutoReader : StringReader
    {
        private readonly Queue<string> lines = new Queue<string>();
        private readonly Queue<char> lastLine = new Queue<char>();

        public CommandLineAutoReader()
            : base(string.Empty)
        {
        }

        public CommandLineAutoReader(string s)
            : base(s)
        {
        }

        public void QueueNext(string s)
        {
            lines.Enqueue(s);
        }

        public override string ReadLine()
        {
            return lines.Dequeue();
        }

        public char ReadKey()
        {
            if (lastLine.Count == 0)
            {
                var line = ReadLine();

                foreach (var c in line)
                {
                    lastLine.Enqueue(c);
                }
            }

            return lastLine.Dequeue();
        }
    }
}
