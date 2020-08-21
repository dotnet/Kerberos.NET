// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Entities
{
    public interface IKerberosMessage
    {
        MessageType KerberosMessageType { get; }

        string Realm { get; }

        int KerberosProtocolVersionNumber { get; }
    }
}