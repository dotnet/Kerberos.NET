using Kerberos.NET.Entities;
using System;
using System.Runtime.Serialization;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET
{

    [Serializable]
    public class KerberosProtocolException : Exception
    {
        public KrbError Error { get; }

        public KerberosProtocolException() { }

        public KerberosProtocolException(KrbError error)
            : this(GetErrorMessage(error))
        {
            Error = error;
        }

        private static string GetErrorMessage(KrbError error)
        {
            if (!string.IsNullOrWhiteSpace(error.EText))
            {
                return error.EText;
            }

            return SR.Resource($"KRB_ERROR_{error.ErrorCode}");
        }

        public KerberosProtocolException(string message) : base(message) { }

        public KerberosProtocolException(string message, Exception inner) : base(message, inner) { }

        protected KerberosProtocolException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
