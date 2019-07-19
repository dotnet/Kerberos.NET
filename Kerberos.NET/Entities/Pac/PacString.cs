using System.IO;

namespace Kerberos.NET.Entities.Pac
{
    public class PacString
    {
        private readonly short Length;
        private readonly short maxLength;
        private readonly int pointer;

        public PacString(short Length, short maxLength, int pointer)
        {
            this.Length = Length;
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

            int expected = Length / 2;

            if (result.Length != expected)
            {
                throw new InvalidDataException($"Read length {result.Length} doesn't match expected length {expected}");
            }

            return result;
        }
    }
}
