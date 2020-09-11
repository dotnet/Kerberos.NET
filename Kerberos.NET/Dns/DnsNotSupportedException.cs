// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.Serialization;

namespace Kerberos.NET.Dns
{

    [Serializable]
    public class DnsNotSupportedException : Exception
    {
        public DnsNotSupportedException()
        {
        }

        public DnsNotSupportedException(string message)
            : base(message)
        {
        }

        public DnsNotSupportedException(string message, Exception inner)
            : base(message, inner)
        {
        }

        protected DnsNotSupportedException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
