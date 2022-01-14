// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Kerberos.NET.Client
{
    internal class FileHandle : IDisposable
    {
        private readonly Mutex mutex;
        private readonly Semaphore semaphore;

        private readonly string file;
        private readonly FileMode mode;
        private readonly FileAccess access;
        private readonly FileShare share;

        private static readonly TimeSpan LockWaitTimeout = TimeSpan.FromMilliseconds(5000);

        public FileHandle(string file, FileMode mode, FileAccess access, FileShare share, int maxReaders = 100)
        {
            var mutexName = GetObjectName(file, "mutex");

            if (Mutex.TryOpenExisting(mutexName, out Mutex mutex))
            {
                this.mutex = mutex;
            }
            else
            {
                this.mutex = new Mutex(false, mutexName);
            }

            var semaphoreName = GetObjectName(file, "semaphore");

            if (Semaphore.TryOpenExisting(semaphoreName, out Semaphore semaphore))
            {
                this.semaphore = semaphore;
            }
            else
            {
                this.semaphore = new Semaphore(maxReaders, maxReaders, semaphoreName);
            }

            this.file = file;
            this.mode = mode;
            this.access = access;
            this.share = share;

            this.MaximumReaders = maxReaders;
        }

        public int MaximumReaders { get; }

        public FileStream OpenStream()
        {
            return File.Open(this.file, this.mode, this.access, this.share);
        }

        public IDisposable AcquireReadLock() => new ReadLock(this.mutex, this.semaphore);

        public IDisposable AcquireWriteLock()
        {
            return new WriteLock(this.mutex, this.semaphore, this.MaximumReaders);
        }

        public void Dispose()
        {
            this.mutex.Dispose();
            this.semaphore.Dispose();
        }

        private static string GetObjectName(string file, string type)
        {
            return "Global\\" + type + "_" + file.Replace(Path.PathSeparator, '_')
                                                 .Replace(Path.DirectorySeparatorChar, '_')
                                                 .Replace(Path.AltDirectorySeparatorChar, '_')
                                                 .Replace(Path.VolumeSeparatorChar, '_');
        }

        private class WriteLock : IDisposable
        {
            private readonly Mutex mutex;
            private readonly Semaphore semaphore;
            private readonly int maximumReaders;

            public WriteLock(Mutex mutex, Semaphore semaphore, int maximumReaders)
            {
                this.mutex = mutex;
                this.semaphore = semaphore;
                this.maximumReaders = maximumReaders;

                this.mutex.WaitOne(LockWaitTimeout);

                for (int i = 0; i < maximumReaders; i++)
                {
                    this.semaphore.WaitOne(LockWaitTimeout);
                }
            }

            public void Dispose()
            {
                this.mutex.ReleaseMutex();

                this.semaphore.Release(this.maximumReaders);
            }
        }

        private class ReadLock : IDisposable
        {
            private readonly Mutex mutex;
            private readonly Semaphore semaphore;

            public ReadLock(Mutex mutex, Semaphore semaphore)
            {
                this.mutex = mutex;
                this.semaphore = semaphore;

                this.mutex.WaitOne(LockWaitTimeout);
                this.semaphore.WaitOne(LockWaitTimeout);
                this.mutex.ReleaseMutex();
            }

            public void Dispose()
            {
                this.semaphore.Release();
            }
        }
    }
}
