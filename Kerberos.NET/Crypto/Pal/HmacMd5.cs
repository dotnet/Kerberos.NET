// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    internal class HmacMd5 : HmacAlgorithmBase
    {
        public HmacMd5(ReadOnlyMemory<byte> key)
            : base(new HMACMD5(TryGetArrayFast(key)))
        {
        }
    }
#endif
}
