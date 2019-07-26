using System;
using System.Collections;
using System.Collections.Generic;

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

        protected NdrMessage(NdrBinaryStream stream)
            : base(stream)
        {

        }

        [KerberosIgnore]
        public RpcHeader Header { get; private set; }

        public virtual void Encode(NdrBinaryStream stream = null)
        {
            if (Header == null)
            {
                Header = new RpcHeader();
            }

            var encodingStream = stream ?? Stream;

            Header.WriteCommonHeader(encodingStream);

            WriteBody(encodingStream);

            encodingStream.WriteDeferred();
        }
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

        public abstract void WriteBody(NdrBinaryStream stream);

        public virtual void WriteBody(NdrBinaryStream stream, Queue<Action> deferredFurther)
        {
            WriteBody(stream);
        }
    }
}
