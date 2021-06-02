using System;
using System.Diagnostics;

namespace Kerberos.NET.Logging
{
    internal class TraceOperation : IDisposable
    {
        public TraceOperation()
        {
            Trace.CorrelationManager.StartLogicalOperation();
        }

        public static IDisposable Start() => new TraceOperation();

        public void Dispose()
        {
            Trace.CorrelationManager.StopLogicalOperation();
        }
    }
}
