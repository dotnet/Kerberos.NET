using Microsoft.Owin.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace KerberosMiddlewareSample
{
    class Program
    {
        private const string NegotiateSample = "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";

        static void Main(string[] args)
        {
            MainAsync().Wait();
        }

        private static async Task MainAsync()
        {
            string baseAddress = "http://localhost:9000/";

            using (WebApp.Start<Startup>(url: baseAddress))
            {
                HttpClient client = new HttpClient();

                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Negotiate", NegotiateSample);

                var response = await client.GetAsync(baseAddress + "api/kerberos");

                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine("=============================");
                Console.WriteLine();

                Console.WriteLine(response);

                var body = await response.Content.ReadAsStringAsync();

                Console.WriteLine(body);
                Console.ReadLine();
            }
        }
    }
}
