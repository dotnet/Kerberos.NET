namespace Kerberos.NET.Entities.Pac
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
            Stream = new NdrBinaryStream(data);
        }

        protected NdrObject(NdrBinaryStream stream)
        {
            Stream = stream;
        }

        [KerberosIgnore]
        protected NdrBinaryStream Stream { get; }
    }
}
