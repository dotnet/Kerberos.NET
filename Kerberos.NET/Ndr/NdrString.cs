using System.Diagnostics;
using System.IO;

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{length} {maxLength} {pointer}")]
    public class NdrString
    {
        private readonly short length;
        private readonly short maxLength;
        private readonly int pointer;

        public NdrString(short length, short maxLength, int pointer)
        {
            this.length = length;
            this.maxLength = maxLength;
            this.pointer = pointer;
        }

        public string ReadString(NdrBinaryStream reader)
        {
            if (pointer == 0)
            {
                return null;
            }

            var result = reader.ReadString(maxLength);

            int expected = length / 2;

            if (result.Length != expected)
            {
                throw new InvalidDataException($"Read length {result.Length} doesn't match expected length {expected}");
            }

            return result;
        }
    }
}
