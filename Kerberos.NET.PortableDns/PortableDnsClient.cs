using DnsClient;
using System.Linq;
using System.Net;

namespace Kerberos.NET.PortableDns
{
    public static class PortableDnsClient
    {
        public static void Configure()
        {
            PortableDnsImplementation.Options = new LookupClientOptions();
        }

        public static void Configure(params NameServer[] nameServers)
        {
            PortableDnsImplementation.Options = new LookupClientOptions(nameServers);
        }

        public static void Configure(params IPEndPoint[] nameServers)
        {
            PortableDnsImplementation.Options = new LookupClientOptions(nameServers);
        }

        public static void Configure(params IPAddress[] nameServers)
        {
            PortableDnsImplementation.Options = new LookupClientOptions(nameServers);
        }

        public static void Configure(params string[] nameServers)
        {
            PortableDnsImplementation.Options = new LookupClientOptions(nameServers.Select(n => {
                var parts = n.Split(':');
                IPAddress address;
                switch (parts.Length)
                {
                    case 1:
                        address = IPAddress.Parse(parts[0]);
                        return new IPEndPoint(address, 53);
                    case 2:
                        address = IPAddress.Parse(parts[0]);
                        var port = int.Parse(parts[1]);
                        return new IPEndPoint(address, port);
                    default:
                        throw new System.FormatException($"{n} is not in the correct format 'IPaddress:Port'");
                }
            }).ToArray());
        }

        public static LookupClientOptions Options => PortableDnsImplementation.Options;
    }
}
