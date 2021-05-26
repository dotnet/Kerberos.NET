// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Crypto
{
    internal abstract class HmacAlgorithmBase : IHmacAlgorithm
    {
        private readonly HMAC hmac;

        protected HmacAlgorithmBase(HMAC hmac)
        {
            this.hmac = hmac;
        }

        public int HashSize => this.hmac.HashSize;

        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> buffer)
        {
            var dataArray = TryGetArrayFast(buffer);

            return this.hmac.ComputeHash(dataArray, 0, buffer.Length);
        }

        public void Dispose()
        {
            this.hmac.Dispose();
        }
    }
}
