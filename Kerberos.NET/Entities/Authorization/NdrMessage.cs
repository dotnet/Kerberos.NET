using System;

namespace Kerberos.NET.Entities.Authorization
{
    public abstract class NdrMessage
    {
        public RpcHeader Header { get; protected set; }
    }
}
