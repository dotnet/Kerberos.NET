// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;

namespace Kerberos.NET.CommandLine
{
    [DebuggerDisplay("{Name}; Required: {Required};")]
    [AttributeUsage(AttributeTargets.Property)]
    public class CommandLineParameterAttribute : Attribute
    {
        public CommandLineParameterAttribute(string name)
        {
            this.Name = name;
        }

        public string Name { get; }

        public string Description { get; set; }

        public bool FormalParameter { get; set; }

        public bool Required { get; set; }

        public bool EnforceCasing { get; set; } = true;
    }
}
