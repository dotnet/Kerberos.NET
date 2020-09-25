// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public interface IKerberosValidator
    {
        ValidationActions ValidateAfterDecrypt { get; set; }

        Task<DecryptedKrbApReq> Validate(byte[] requestBytes);

        Task<DecryptedKrbApReq> Validate(ReadOnlyMemory<byte> requestBytes);

        void Validate(PrivilegedAttributeCertificate pac, KrbPrincipalName sname);
    }
}
