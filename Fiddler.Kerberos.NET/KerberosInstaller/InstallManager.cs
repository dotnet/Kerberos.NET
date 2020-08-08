using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Squirrel;

namespace Fiddler.Kerberos.NET
{
    public static class InstallManager
    {
        public static void Setup()
        {
            SquirrelAwareApp.HandleEvents(
                onInitialInstall: v => CopyFiles(),
                onAppUpdate: v => CopyFiles(),
                onAppUninstall: v => DeleteFiles(),
                onFirstRun: () => { }
            );
        }

        private static bool running;

        public static void Watch()
        {
            if (running)
            {
                return;
            }

            running = true;

            Task.Run(Update);
        }

        private static async Task Update()
        {
            try
            {
                using (var mgr = await UpdateManager.GitHubUpdateManager("https://github.com/dotnet/Kerberos.NET"))
                {
                    await mgr.UpdateApp();
                }
            }
            catch
            {
                return;
            }
        }

        private static void DeleteFiles()
        {
            var files = GetPluginFiles();

            foreach (var file in files)
            {
                var name = Path.GetFileName(file);

                var inspectorPath = GetInspectorPath(name);

                try
                {
                    if (File.Exists(inspectorPath))
                    {
                        File.Delete(inspectorPath);
                    }
                }
                catch
                {
                    ;
                }
            }
        }

        private static void CopyFiles()
        {
            string[] files = GetPluginFiles();

            foreach (var file in files)
            {
                var name = Path.GetFileName(file);
                var targetPath = GetInspectorPath(name);

                File.Copy(
                    file,
                    targetPath,
                    overwrite: true
                );
            }
        }

        private static string GetInspectorPath(string file)
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + $"\\fiddler2\\inspectors\\{file}";
        }

        private static string[] GetPluginFiles()
        {
            var directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

            return Directory.GetFiles(directory, "*.dll");
        }
    }
}
