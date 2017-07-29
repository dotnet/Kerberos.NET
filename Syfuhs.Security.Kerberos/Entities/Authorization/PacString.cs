using System.IO;

namespace Syfuhs.Security.Kerberos.Entities.Authorization
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

        public string ReadString(NdrBinaryReader reader)
        {
            var result = reader.ReadString();

            int expected = Length / 2;

            if (result.Length != expected)
            {
                throw new InvalidDataException($"Read length {result.Length} doesn't match expected length {expected}");
            }

            return result;
        }
    }
}
