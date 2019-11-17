using Tests.Kerberos.NET;

namespace RpcEncodingDebugHost
{
    class Program
    {
        static void Main(string[] args)
        {
            RpcInteropTests test = new RpcInteropTests();

            //test.MarshalNativeFromManaged_Baseline_DoesntExplode();

            test.MarshalNativeFromNative_PassThroughManaged();
        }
    }
}
