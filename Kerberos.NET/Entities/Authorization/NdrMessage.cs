namespace Kerberos.NET.Entities.Authorization
{
    public abstract class NdrMessage : NdrObject
    {
        protected NdrMessage(byte[] data)
            : base(data)
        {
            if ((data?.Length ?? 0) <= 0)
            {
                return;
            }

            Header = Stream.ReadNdrHeader();
        }

        [KerberosIgnore]
        public RpcHeader Header { get; }
    }

    public abstract class NdrObject
    {
        protected NdrObject(byte[] data)
        {
            Stream = new NdrBinaryReader(data);
        }

        protected NdrObject(NdrBinaryReader stream)
        {
            Stream = stream;
        }

        [KerberosIgnore]
        protected NdrBinaryReader Stream { get; }
    }
}
