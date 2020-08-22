// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Runtime.InteropServices;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public unsafe class KerbServiceTargetRestriction : Restriction
    {
        public KerbServiceTargetRestriction(KrbAuthorizationData authz)
            : base(authz?.Type ?? 0, AuthorizationDataType.KerbServiceTarget)
        {
            this.ServiceName = MemoryMarshal.Cast<byte, char>(authz.Data.Span).ToString();
        }

        public string ServiceName { get; }

        public override string ToString()
        {
            return this.ServiceName;
        }
    }
}