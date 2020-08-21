// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security;

namespace Kerberos.NET
{
    [Serializable]
    public class KerberosValidationException : SecurityException
    {
        public KerberosValidationException(string message, string parameter = null)
            : base(message)
        {
            this.Parameter = parameter;
        }

        public KerberosValidationException(string message, Exception inner)
            : base(message, inner)
        {
        }

        public string Parameter { get; }

        public KerberosValidationException()
        {
        }

        public KerberosValidationException(string message)
            : base(message)
        {
        }

        protected KerberosValidationException(System.Runtime.Serialization.SerializationInfo serializationInfo, System.Runtime.Serialization.StreamingContext streamingContext)
        {
            throw new NotImplementedException();
        }
    }
}