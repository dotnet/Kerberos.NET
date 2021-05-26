// -----------------------------------------------------------------------
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

#pragma warning disable CA1717 // Only FlagsAttribute enums should have plural names

namespace Kerberos.NET.Entities
{
    public enum FastOptions
    {
        Reserved = 0,

        /// <summary>
        /// Requesting the KDC to hide client names in the KDC response.
        /// </summary>
        HideClientNames = 1 << 31,
    }
}
