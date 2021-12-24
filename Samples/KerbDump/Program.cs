using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace KerbDump
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            AppDomain.CurrentDomain.AssemblyResolve += CurrentDomain_AssemblyResolve;
            AppDomain.CurrentDomain.AssemblyLoad += CurrentDomain_AssemblyLoad;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new DecoderForm());
        }

        private static void CurrentDomain_AssemblyLoad(object sender, AssemblyLoadEventArgs args)
        {
            Debug.WriteLine(args.LoadedAssembly);
        }

        private static System.Reflection.Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            Debug.WriteLine(args.Name);

            return null;
        }
    }
}
