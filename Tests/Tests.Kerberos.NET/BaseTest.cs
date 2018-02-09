using System.IO;

namespace Tests.Kerberos.NET
{
    public abstract class BaseTest
    {
        protected byte[] ReadFile(string name)
        {
            return File.ReadAllBytes($"data{Path.DirectorySeparatorChar}{name}");
        }
    }
}