using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using LogFunc = System.Action<
    System.Diagnostics.TraceLevel,
    string,
    int,
    object,
    object,
    System.Exception,
    string>;

namespace Kerberos.NET.Logging
{
    public class KerberosDelegateLogger : ILoggerFactory
    {
        private readonly LogFunc log;

        public KerberosDelegateLogger(LogFunc action)
        {
            log = action;
        }

        public void AddProvider(ILoggerProvider provider) { }

        public ILogger CreateLogger(string categoryName)
        {
            return new DelegateLogger(log, categoryName);
        }

        public void Dispose() { }

        private class DelegateLogger : ILogger
        {
            private readonly LogFunc log;
            private readonly string categoryName;

            private readonly ConcurrentStack<LoggerScope> scopes = new ConcurrentStack<LoggerScope>();

            private readonly LoggerScope defaultScope;

            private LoggerScope Scope
            {
                get
                {
                    if (scopes.TryPeek(out LoggerScope scope))
                    {
                        return scope;
                    }

                    return defaultScope;
                }
            }

            public DelegateLogger(LogFunc log, string categoryName)
            {
                this.log = log;
                this.categoryName = categoryName;

                defaultScope = new LoggerScope(null, log, categoryName, scopes);
            }

            public IDisposable BeginScope<TState>(TState state)
            {
                var scope = new LoggerScope(state, log, categoryName, scopes);

                scopes.Push(scope);

                return scope;
            }

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                Scope.Log(logLevel, eventId, state, exception, formatter);
            }

            private class LoggerScope : IDisposable
            {
                private readonly object state;
                private readonly LogFunc log;
                private readonly string categoryName;
                private readonly ConcurrentStack<LoggerScope> scopes;

                public LoggerScope(object state, LogFunc log, string categoryName, ConcurrentStack<LoggerScope> scopes)
                {
                    this.state = state;
                    this.log = log;
                    this.categoryName = categoryName;
                    this.scopes = scopes;
                }

                public void Dispose()
                {
                    while (scopes.TryPop(out LoggerScope scope))
                    {
                        if (ReferenceEquals(scope, this))
                        {
                            break;
                        }
                    }
                }

                internal void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
                {
                    TraceLevel level = ConvertLogLevel(logLevel);

                    log(level, categoryName, eventId.Id, this.state, state, exception, formatter(state, exception));
                }

                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                private static TraceLevel ConvertLogLevel(LogLevel logLevel)
                {
                    TraceLevel level;

                    switch (logLevel)
                    {
                        case LogLevel.Trace:
                        case LogLevel.Debug:
                            level = TraceLevel.Verbose;
                            break;
                        case LogLevel.Information:
                            level = TraceLevel.Info;
                            break;
                        case LogLevel.Warning:
                            level = TraceLevel.Warning;
                            break;
                        case LogLevel.Error:
                        case LogLevel.Critical:
                            level = TraceLevel.Error;
                            break;
                        case LogLevel.None:
                            level = TraceLevel.Off;
                            break;
                        default:
                            level = TraceLevel.Verbose;
                            break;
                    }

                    return level;
                }
            }
        }
    }
}
