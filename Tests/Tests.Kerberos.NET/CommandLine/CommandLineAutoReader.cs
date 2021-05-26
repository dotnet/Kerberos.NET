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
            this.lines.Enqueue(s);
        }

        public override string ReadLine()
        {
            return this.lines.Dequeue();
        }

        public char ReadKey()
        {
            if (this.lastLine.Count == 0)
            {
                var line = this.ReadLine();

                foreach (var c in line)
                {
                    this.lastLine.Enqueue(c);
                }
            }

            return this.lastLine.Dequeue();
        }
    }
}
