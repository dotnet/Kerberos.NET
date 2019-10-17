using System;
using System.Collections.Generic;

namespace Kerberos.NET.Entities.Pac
{
    public abstract class NdrMessage : NdrObject
    {
        [KerberosIgnore]
        public RpcHeader Header { get; private set; }

        public virtual void Decode(ReadOnlyMemory<byte> data)
        {
            var stream = new NdrBinaryStream(data);

            Header = stream.ReadNdrHeader();

            ReadBody(stream);
        }

        public virtual void Encode(NdrBinaryStream stream)
        {
            if (Header == null)
            {
                Header = new RpcHeader();
            }

            Header.WriteCommonHeader(stream);

            stream.Align(4);

            WriteBody(stream);

            stream.WriteDeferred();
        }

        private ReadOnlyMemory<byte> cachedEncodedValue;

        public override ReadOnlyMemory<byte> Encode()
        {
            if (cachedEncodedValue.Length <= 0 || IsDirty)
            {
                var stream = new NdrBinaryStream();

                Encode(stream);

                cachedEncodedValue = stream.ToMemory();

                IsDirty = false;
            }

            return cachedEncodedValue;
        }
    }

    public abstract class NdrObject
    {
        public abstract void WriteBody(NdrBinaryStream stream);

        public virtual void WriteBody(NdrBinaryStream stream, Queue<Action> deferredFurther)
        {
            WriteBody(stream);
        }

        public abstract void ReadBody(NdrBinaryStream stream);

        public virtual void ReadBody(ReadOnlyMemory<byte> data)
        {
            ReadBody(new NdrBinaryStream(data));
        }

        protected bool IsDirty { get; set; }

        private ReadOnlyMemory<byte> cachedEncodedValue;

        public virtual ReadOnlyMemory<byte> Encode()
        {
            if (cachedEncodedValue.Length <= 0 || IsDirty)
            {
                var stream = new NdrBinaryStream();

                WriteBody(stream);

                cachedEncodedValue = stream.ToMemory();

                IsDirty = false;
            }

            return cachedEncodedValue;
        }
    }
}
