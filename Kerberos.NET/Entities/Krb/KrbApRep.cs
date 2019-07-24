namespace Kerberos.NET.Entities
{
    public partial class KrbApRep
    {
        public KrbApRep()
        {
            ProtocolVersionNumber = 5;
            MessageType = MessageType.KRB_AP_REP;
        }
    }
}
