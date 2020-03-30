using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Diagnostics;

namespace Microsoft.Extensions.Logging
{
    internal static class LoggerExtensions
    {
        private static readonly Func<ILogger, Guid, IDisposable> beginRequestScope;
        private static readonly Action<ILogger, KerberosProtocolException> logProtocolException;
        private static readonly Action<ILogger, string, Exception> logBinaryTraceData;

        static LoggerExtensions()
        {
            beginRequestScope = LoggerMessage.DefineScope<Guid>("Request => {RequestScope}");
            logProtocolException = LoggerMessage.Define(LogLevel.Warning, new EventId(), "Protocol failure");
            logBinaryTraceData = LoggerMessage.Define<string>(LogLevel.Trace, new EventId(), "Traced binary data {Data}");
        }

        public static IDisposable BeginRequestScope(this ILogger logger, Guid scopeId)
        {
            Trace.CorrelationManager.ActivityId = scopeId;

            return beginRequestScope(logger, Trace.CorrelationManager.ActivityId);
        }

        public static void LogKerberosProtocolException(this ILogger logger, KerberosProtocolException pex)
        {
            logProtocolException(logger, pex);
        }

        public static void TraceBinary(this ILogger logger, ReadOnlyMemory<byte> data)
        {
            if (logger.IsEnabled(LogLevel.Trace))
            {
                logBinaryTraceData(logger, Environment.NewLine + data.ToArray().HexDump(), null);
            }
        }

        public static ILogger<T> CreateLoggerSafe<T>(this ILoggerFactory factory)
        {
            if (factory == null)
            {
                return NullLoggerFactory.Instance.CreateLogger<T>();
            }

            return factory.CreateLogger<T>();
        }
    }
}
