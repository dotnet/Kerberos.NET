using System;

namespace Kerberos.NET.Entities
{
    public class PacDecodeError
    {
        public PacType Type { get; set; }

        public byte[] Data { get; set; }

        public Exception Exception { get; set; }
    }
}