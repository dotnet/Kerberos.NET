// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Buffers.Binary;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public class KerbApOptionsRestriction : Restriction
    {
        public KerbApOptionsRestriction(KrbAuthorizationData authz)
            : base(authz?.Type ?? 0, AuthorizationDataType.KerbApOptions)
        {
            this.Options = (ApOptions)BinaryPrimitives.ReadInt32LittleEndian(authz.Data.Span);
        }

        public ApOptions Options { get; }

        public override string ToString()
        {
            return this.Options.ToString();
        }
    }
}