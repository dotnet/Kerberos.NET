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
            MechType = mechType;
        }
    }
}
