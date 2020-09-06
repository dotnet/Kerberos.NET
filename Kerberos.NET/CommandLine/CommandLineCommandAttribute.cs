// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.CommandLine
{
    [AttributeUsage(AttributeTargets.Class)]
    public class CommandLineCommandAttribute : Attribute
    {
        public CommandLineCommandAttribute(string command)
        {
            this.Command = command;
        }

        public string Command { get; }

        public string Description { get; set; }
    }
}
