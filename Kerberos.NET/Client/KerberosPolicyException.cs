using System;
using System.Runtime.Serialization;
using Kerberos.NET.Entities;
using Kerberos.NET.Win32;

namespace Kerberos.NET.Client
{
    [Serializable]
    public class KerberosPolicyException : Exception
    {
        public KerberosPolicyException(Win32StatusCode statusCode)
        {
            this.StatusCode = statusCode;
        }

        public KerberosPolicyException(PaDataType requestedType)
        {
            this.RequestedType = requestedType;
        }

        public KerberosPolicyException(string message)
            : base(message)
        {
        }

        public KerberosPolicyException(string message, Exception inner)
            : base(message, inner)
        {
        }

        protected KerberosPolicyException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        public Win32StatusCode? StatusCode { get; }

        public PaDataType? RequestedType { get; }
    }
}
