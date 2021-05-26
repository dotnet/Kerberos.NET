// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.Serialization;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    [Serializable]
    public class KerberosProtocolException : Exception
    {
        public KrbError Error { get; }

        public KerberosProtocolException()
        {
        }

        public KerberosProtocolException(KerberosErrorCode error, string etext = null)
            : this(new KrbError() { ErrorCode = error, EText = etext })
        {
        }

        public KerberosProtocolException(KrbError error)
            : this(GetErrorMessage(error))
        {
            this.Error = error;
        }

        private static string GetErrorMessage(KrbError error)
        {
            if (!string.IsNullOrWhiteSpace(error.EText))
            {
                return error.EText;
            }

            return $"KDC {error.ErrorCode}: {GetErrorMessage(error.ErrorCode)}";
        }

        public static string GetErrorMessage(KerberosErrorCode error)
        {
            return SR.Resource($"KRB_ERROR_{error}");
        }

        public KerberosProtocolException(string message)
            : base(message)
        {
        }

        public KerberosProtocolException(string message, Exception inner)
            : base(message, inner)
        {
        }

        protected KerberosProtocolException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}