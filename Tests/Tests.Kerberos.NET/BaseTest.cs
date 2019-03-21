using Kerberos.NET;
using System.IO;

namespace Tests.Kerberos.NET
{
    public abstract class BaseTest
    {
        public const ValidationActions DefaultActions = ValidationActions.All & (~(ValidationActions.EndTime | ValidationActions.StartTime | ValidationActions.TokenWindow));

        protected byte[] ReadFile(string name)
        {
            return File.ReadAllBytes($"data{Path.DirectorySeparatorChar}{name}");
        }
    }
}