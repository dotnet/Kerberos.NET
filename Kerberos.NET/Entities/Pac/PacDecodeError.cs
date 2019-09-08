using System;

namespace Kerberos.NET.Entities
{
    public class PacDecodeError
    {
        public PacType Type { get; set; }

        public ReadOnlyMemory<byte> Data { get; set; }

        public Exception Exception { get; set; }
    }
}