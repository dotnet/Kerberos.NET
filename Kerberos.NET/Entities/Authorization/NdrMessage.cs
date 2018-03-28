using System;

namespace Kerberos.NET.Entities.Authorization
{
    public abstract class NdrMessage
    {
        [KerberosIgnore]
        public RpcHeader Header { get; protected set; }
    }
}
