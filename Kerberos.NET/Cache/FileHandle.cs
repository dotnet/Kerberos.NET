// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Threading;

namespace Kerberos.NET.Client
{
    internal class FileHandle : IDisposable
    {
        private readonly Mutex mutex;

        private readonly string file;
        private readonly FileMode mode;
        private readonly FileAccess access;
        private readonly FileShare share;

        private static readonly TimeSpan LockWaitTimeout = TimeSpan.FromMilliseconds(5000);

        public FileHandle(string file, FileMode mode, FileAccess access, FileShare share)
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

            this.file = file;
            this.mode = mode;
            this.access = access;
            this.share = share;
        }

        public FileStream OpenStream()
        {
            return File.Open(this.file, this.mode, this.access, this.share);
        }

        public IDisposable AcquireReadLock() => new FileLock(this.mutex);

        public IDisposable AcquireWriteLock() => new FileLock(this.mutex);

        public void Dispose()
        {
            this.mutex.Dispose();
        }

        private static string GetObjectName(string file, string type)
        {
            return "Global\\" + type + "_" + file.Replace(Path.DirectorySeparatorChar, '_')
                                                 .Replace(Path.AltDirectorySeparatorChar, '_')
                                                 .Replace(Path.VolumeSeparatorChar, '_');
        }

        private class FileLock : IDisposable
        {
            private readonly Mutex mutex;

            public FileLock(Mutex mutex)
            {
                this.mutex = mutex;

                this.mutex.WaitOne(LockWaitTimeout);
            }

            public void Dispose()
            {
                this.mutex.ReleaseMutex();
            }
        }
    }
}
