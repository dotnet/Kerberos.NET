using System;
using System.IO;

namespace Tests.Kerberos.NET
{
    internal class TemporaryFile : IDisposable
    {
        private readonly string file;

        public TemporaryFile(string file = null)
        {
            this.file = file ?? Path.GetTempFileName();
        }

        public string File => this.file;

        public void Dispose()
        {
            try {
                System.IO.File.Delete(this.file);
            }
            catch { }
        }
    }
}
