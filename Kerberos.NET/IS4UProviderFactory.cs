// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Crypto;

namespace Kerberos.NET
{
    internal interface IS4UProviderFactory
    {
        IS4UProvider CreateProvider(DecryptedKrbApReq krbApReq);
    }
}
