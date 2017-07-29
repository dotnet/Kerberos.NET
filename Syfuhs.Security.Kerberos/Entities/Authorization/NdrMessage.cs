using System;

namespace Syfuhs.Security.Kerberos.Entities.Authorization
{
    public abstract class NdrMessage
    {
        public RpcHeader Header { get; protected set; }
    }
}
