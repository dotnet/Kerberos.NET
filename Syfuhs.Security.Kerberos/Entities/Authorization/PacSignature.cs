
namespace Syfuhs.Security.Kerberos.Entities.Authorization
{
    public class PacSignature
    {
        public PacSignature(byte[] data)
        {
            var pacStream = new PacBinaryReader(data);

            Type = pacStream.ReadInt();
            Signature = pacStream.ReadToEnd();
        }

        public int Type { get; private set; }

        public byte[] Signature { get; private set; }
    }
}
