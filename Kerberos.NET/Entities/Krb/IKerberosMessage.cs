
namespace Kerberos.NET.Entities
{
    public interface IKerberosMessage
    {
        MessageType KerberosMessageType { get; }

        string Realm { get; }

        int KerberosProtocolVersionNumber { get; }
    }
}
