using System.IO;

namespace Kerberos.NET.Entities
{
    public static class BinaryReaderExtensions
    {
        public static long BytesAvailable(this BinaryReader reader)
        {
            return reader.BaseStream.Length - reader.BaseStream.Position;
        }
    }
}
