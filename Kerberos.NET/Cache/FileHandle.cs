// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------
#nullable enable

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Kerberos.NET.Client
{
    internal class FileHandle : IDisposable
    {
        private readonly Mutex mutex;

        private readonly string file;
        private readonly FileMode mode;
        private readonly FileAccess access;
        private readonly FileShare share;
        private static readonly MethodInfo? SetUnixFileMode = TryGetSetUnixFileMode();

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
            var fs = File.Open(this.file, this.mode, this.access, this.share);
            // When we create file on Unix we should make sure only current user has access to it.
            if (this.access == FileAccess.Write && SetUnixFileMode != null)
            {
                const int UserRead = 256;
                const int UserWrite = 128;

                try
                {
                    SetUnixFileMode.Invoke(null, new object[] { fs.SafeFileHandle, (int)(UserRead | UserWrite) });
                }
                catch { };
            }

            return fs;
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

        private static MethodInfo? TryGetSetUnixFileMode()
        {
            MethodInfo? mi = null;

            // SetUnixFileMode was introduced in .NET 7.0 and works only on Unix systems
            // We ignore any reflection errors during attempt to load it.
            if (!RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            {
                try
                {
                    mi = typeof(File).GetMethod("SetUnixFileMode", new Type[] { typeof(SafeFileHandle), Type.GetType("System.IO.UnixFileMode") });
                }
                catch { }
            }

            return mi;
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
