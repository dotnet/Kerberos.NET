// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.ComponentModel;

namespace Kerberos.NET.Configuration
{
    public class Krb5Logging
    {
        [DisplayName("kdc")]
        public string Kdc { get; set; }

        [DisplayName("admin_server")]
        public string AdminServer { get; set; }

        [DisplayName("default")]
        public string Default { get; set; }
    }
}
