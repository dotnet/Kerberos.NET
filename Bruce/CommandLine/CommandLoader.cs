// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;

namespace Kerberos.NET.CommandLine
{
    internal static class CommandLoader
    {
        public static ICommand CreateCommandExecutor(
            string commandValue,
            CommandLineParameters instance,
            InputControl io
        )
        {
            var types = LoadTypes();

            foreach (var type in types)
            {
                var attr = type.GetCustomAttribute<CommandLineCommandAttribute>();

                var allCommands = attr.Command.Split('|');

                foreach (var commandStr in allCommands)
                {
                    if (string.Equals(commandValue, commandStr, StringComparison.InvariantCultureIgnoreCase))
                    {
                        var ctor = type.GetConstructor(new[] { typeof(CommandLineParameters) });

                        ICommand command;

                        if (ctor != null)
                        {
                            command = (ICommand)ctor.Invoke(new[] { instance });
                        }
                        else
                        {
                            command = (ICommand)Activator.CreateInstance(type);
                        }

                        command.IO = io;

                        return command;
                    }
                }
            }

            return null;
        }

        internal static IEnumerable<Type> LoadTypes()
        {
            IEnumerable<Assembly> assemblies = LoadAssemblies();

            foreach (var assembly in assemblies)
            {
                var types = assembly.GetTypes().Where(t => t.GetCustomAttribute<CommandLineCommandAttribute>() != null);

                foreach (var type in types)
                {
                    yield return type;
                }
            }
        }

        private static IEnumerable<Assembly> LoadAssemblies()
        {
            var assemblies = new HashSet<Assembly>();

            var entry = Assembly.GetExecutingAssembly();

            assemblies.Add(entry);

            var folder = Path.GetDirectoryName(entry.Location);

            var dlls = Directory.GetFiles(folder, "*.dll");

            foreach (var dll in dlls)
            {
                try
                {
                    var loaded = Assembly.LoadFile(dll);

                    if (!assemblies.Any(a => a.FullName == loaded.FullName))
                    {
                        assemblies.Add(loaded);
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(ex);
                }
            }

            return assemblies;
        }
    }
}
