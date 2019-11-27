using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using System;
using System.Threading.Tasks;

namespace SaltQuery
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // administrator@{...}corp.microsoft.com doesn't exist
            var credential = new KerberosPasswordCredential("stsyfuhs@redmond.corp.microsoft.com", "password not required for this");

            var asReqMessage = KrbAsReq.CreateAsReq(credential, AuthenticationOptions.Renewable);

            var asReq = asReqMessage.EncodeApplication();

            // TCP connection errors aren't handled well at this layer
            // Just shove an IP in TcpKerberosTransport(null, kdc: "10.221.192.74:88")

            var transport = new TcpKerberosTransport(null) { ConnectTimeout = TimeSpan.FromSeconds(5) };

            try
            {
                var asRep = await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);
            }
            catch (KerberosProtocolException pex)
            {
                Console.WriteLine($"Got an error: {pex.Message} (EText: {pex?.Error?.EText})");
                Console.WriteLine("");

                var paData = pex?.Error?.DecodePreAuthentication();

                if (paData != null)
                {
                    foreach (var pa in paData)
                    {
                        if (pa.Type != PaDataType.PA_ETYPE_INFO2)
                        {
                            continue;
                        }

                        var etypeData = pa.DecodeETypeInfo2();

                        Console.WriteLine($"KDC Supported ETypes for principal {credential.UserName}");
                        Console.WriteLine();

                        foreach (var etype in etypeData)
                        {
                            string s2k = null;

                            if (etype.S2kParams.HasValue)
                            {
                                s2k = Hex.DumpHex(etype.S2kParams.Value);
                            }

                            Console.WriteLine($"Etype: {etype.EType}");
                            Console.WriteLine($"Salt: {etype.Salt}");
                            Console.WriteLine($"S2K: {etype.S2kParams}");
                            Console.WriteLine();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"No idea: {ex.Message}");
            }
        }
    }
}
