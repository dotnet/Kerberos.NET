using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Tests.Kerberos.NET
{
    internal class FakeExceptionLoggerFactory : ILoggerFactory
    {
        private readonly ConcurrentBag<Exception> exceptions = new ConcurrentBag<Exception>();
        private readonly ConcurrentBag<string> logs = new ConcurrentBag<string>();

        public IEnumerable<Exception> Exceptions => exceptions;

        public IEnumerable<string> Logs => logs;

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new ExceptionLogger(exceptions, logs);
        }

        public void Dispose()
        {

        }

        private class ExceptionLogger : ILogger
        {
            private readonly ConcurrentBag<Exception> exceptions;
            private readonly ConcurrentBag<string> logs;

            public ExceptionLogger(ConcurrentBag<Exception> exceptions, ConcurrentBag<string> logs)
            {
                this.exceptions = exceptions;
                this.logs = logs;
            }

            private class Scope : IDisposable
            {
                public void Dispose() { }
            }

            public IDisposable BeginScope<TState>(TState state)
            {
                return new Scope();
            }

            public bool IsEnabled(LogLevel logLevel)
            {
                return true;
            }

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                if (exception != null)
                {
                    exceptions.Add(exception);
                }

                logs.Add($"[{logLevel}] {eventId} " + formatter(state, exception));
            }
        }
    }
}
