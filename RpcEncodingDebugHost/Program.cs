using Tests.Kerberos.NET;

namespace RpcEncodingDebugHost
{
    class Program
    {
        static void Main(string[] args)
        {
            DiffieHellmanKeyAgreementTests test = new DiffieHellmanKeyAgreementTests();

            test.Oakley14_KeyAgreement();

            //RpcInteropTests test = new RpcInteropTests();

            //test.MarshalNativeFromManaged_Baseline_DoesntExplode();

            //test.MarshalNativeFromNative_PassThroughManaged();
        }
    }
}
