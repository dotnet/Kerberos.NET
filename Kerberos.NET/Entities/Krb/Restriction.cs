// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public abstract class Restriction
    {
        protected Restriction()
        {
        }

        protected Restriction(AuthorizationDataType actualType, AuthorizationDataType expectedType)
        {
            if (actualType != expectedType)
            {
                throw new InvalidOperationException($"Cannot create {expectedType} because actual type is {actualType}");
            }

            this.Type = actualType;
        }

        public AuthorizationDataType Type { get; }
    }
}