// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Configuration
{
    /// <summary>
    /// Indicates that the represented IEnumerable should be separated by commas instead of spaces
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    internal class CommaSeparatedListAttribute : Attribute
    {
    }
}
