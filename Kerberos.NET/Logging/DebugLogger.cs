using System;
using System.Diagnostics;
using System.Text;

namespace Kerberos.NET
{
    internal class DebugLogger : ILogger
    {
        public LogLevel Level { get; set; } = LogLevel.Debug;

        public bool Enabled { get; set; } = true;

        public void WriteLine(KerberosLogSource source, string value)
        {
            if (!Enabled)
            {
                return;
            }

            Debug.WriteLine($"[{source}] {value}");
        }

        public void WriteLine(KerberosLogSource source, string value, Exception ex)
        {
            if (!Enabled)
            {
                return;
            }

            Debug.WriteLine($"[{source}] {value}");

            WriteLine(source, ex);
        }

        public void WriteLine(KerberosLogSource source, Exception ex)
        {
            if (!Enabled)
            {
                return;
            }

            var exValue = new StringBuilder();

            if (ex is AggregateException agg)
            {
                for (var i = 0; i < agg.InnerExceptions.Count; i++)
                {
                    exValue.AppendFormat($"\r\n[{source}]\t[{i}] {agg.InnerExceptions[i]}");
                }
            }

            Debug.WriteLine(exValue);
        }
    }
}