// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public class KerbLocalRestriction : Restriction
    {
        public KerbLocalRestriction(KrbAuthorizationData authz)
            : base(authz?.Type ?? 0, AuthorizationDataType.KerbLocal)
        {
            this.Value = new ReadOnlySequence<byte>(authz.Data);
        }

        public ReadOnlySequence<byte> Value { get; }

        public override string ToString()
        {
            return Convert.ToBase64String(this.Value.ToArray());
        }
    }
}