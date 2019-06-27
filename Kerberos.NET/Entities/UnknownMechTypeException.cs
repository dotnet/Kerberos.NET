using System;

namespace Kerberos.NET.Entities
{
    [Serializable]
    public class UnknownMechTypeException : Exception
    {
        public UnknownMechTypeException()
        {
        }

        public string MechType { get; }

        public UnknownMechTypeException(string mechType)
            : base($"An unknown MechType ({mechType}) was presented and the parser could not proceed.")
        {
            MechType = mechType;
        }

        public UnknownMechTypeException(string mechType, string message) 
            : base(message)
        {
            MechType = mechType;
        }

        public UnknownMechTypeException(string message, Exception innerException) 
            : base(message, innerException)
        {
        }
    }
}