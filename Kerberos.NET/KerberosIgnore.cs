// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics.CodeAnalysis;

namespace Kerberos.NET
{
    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
    public sealed class KerberosIgnoreAttribute : Attribute
    {
        public KerberosIgnoreAttribute()
        {
        }
    }
}