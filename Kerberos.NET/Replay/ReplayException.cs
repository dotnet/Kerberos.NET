// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET
{
    [Serializable]
    public class ReplayException : KerberosValidationException
    {
        public ReplayException(string message)
            : base(message)
        {
        }

        public ReplayException()
        {
        }

        public ReplayException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected ReplayException(System.Runtime.Serialization.SerializationInfo serializationInfo, System.Runtime.Serialization.StreamingContext streamingContext)
        {
            throw new NotImplementedException();
        }
    }
}