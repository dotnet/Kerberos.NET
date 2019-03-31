namespace Kerberos.NET.Crypto
{
    public static class Endian
    {
        public static void ConvertToBigEndian(int val, byte[] bytes, int offset)
        {
            bytes[offset + 0] = (byte)((val >> 24) & 0xff);
            bytes[offset + 1] = (byte)((val >> 16) & 0xff);
            bytes[offset + 2] = (byte)((val >> 8) & 0xff);
            bytes[offset + 3] = (byte)((val) & 0xff);
        }

        public static void ConvertToLittleEndian(int val, byte[] bytes, int offset)
        {
            bytes[offset + 0] = (byte)(val & 0xFF);
            bytes[offset + 1] = (byte)((val >> 8) & 0xFF);
            bytes[offset + 2] = (byte)((val >> 16) & 0xFF);
            bytes[offset + 3] = (byte)((val >> 24) & 0xFF);
        }
    }
}