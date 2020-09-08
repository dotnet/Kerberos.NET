// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;

namespace Kerberos.NET.CommandLine
{
    /// <summary>
    /// Control class for reading and writing from a console-like interface.
    /// </summary>
    public class InputControl
    {
        /// <summary>
        /// Write text to the screen.
        /// </summary>
        public TextWriter Writer { get; set; }

        /// <summary>
        /// Read text from the screen.
        /// </summary>
        public TextReader Reader { get; set; }

        /// <summary>
        /// Clear the screen.
        /// </summary>
        public Action Clear { get; set; }

        /// <summary>
        /// Read a single key press.
        /// </summary>
        public Func<ConsoleKeyInfo> ReadKey { get; set; }

        /// <summary>
        /// Controls whether the console should pass the Ctrl+C key press to a reader instead of closing the process.
        /// </summary>
        public Action<bool> HookCtrlC { get; set; }
    }
}
