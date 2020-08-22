// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Transport
{
    [ExcludeFromCodeCoverage]
    [Serializable]
    public class KerberosTransportException : KerberosProtocolException
    {
        public KerberosTransportException()
        {
        }

        public KerberosTransportException(KrbError error)
            : base(error)
        {
        }

        public KerberosTransportException(string message)
            : base(message)
        {
        }

        public KerberosTransportException(string message, Exception inner)
            : base(message, inner)
        {
        }

        protected KerberosTransportException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}