// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Configuration
{
    public abstract class Krb5ConfigObject
    {
        public virtual ConfigurationSectionList OptionalProperties { get; } = new ConfigurationSectionList();
    }
}
