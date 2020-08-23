// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Configuration
{
    /// <summary>
    /// Indicates a value normally represented by an Enum named value should be represented by the integer value instead.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property)]
    internal class EnumAsIntegerAttribute : Attribute
    {
    }
}
