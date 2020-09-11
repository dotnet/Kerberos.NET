// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    public interface ICommand
    {
        InputControl IO { get; set; }

        Task<bool> Execute();

        void DisplayHelp();
    }
}
