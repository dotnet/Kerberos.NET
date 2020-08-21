// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    [Serializable]
    public class UnknownMechTypeException : Exception
    {
        public string MechType { get; }

        public UnknownMechTypeException(string mechType)
            : this(mechType, $"An unknown MechType ({mechType}) was presented and the parser could not proceed.")
        {
        }

        public UnknownMechTypeException(string mechType, string message)
            : base(message)
        {
            this.MechType = mechType;
        }

        public UnknownMechTypeException()
        {
        }

        public UnknownMechTypeException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected UnknownMechTypeException(System.Runtime.Serialization.SerializationInfo serializationInfo, System.Runtime.Serialization.StreamingContext streamingContext)
        {
            throw new NotImplementedException();
        }
    }
}