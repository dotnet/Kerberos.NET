namespace Kerberos.NET.Server
{
    public class KdcServiceListener : ServiceListenerBase
    {
        public KdcServiceListener(ListenerOptions options)
            : base(options, (socket, o) => new KdcSocketWorker(socket, o))
        {

        }
    }
}
