using System.Diagnostics;

namespace Kerberos.NET
{
    internal class DebugLogger : ILogger
    {
        public void WriteLine(string value)
        {
            Debug.WriteLine(value);
        }
    }
}