using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using SectionList = System.Collections.Generic.List<System.Collections.Generic.KeyValuePair<string, object>>;

namespace Kerberos.NET.Configuration
{
    [DebuggerDisplay("{Name}, {Configuration.Count}")]
    public class Krb5Configuration
    {
        public string Name { get; set; }

        public SectionList Configuration { get; set; } = new SectionList();

        private const char Comment = '#';
        private const char SectionOpen = '[';
        private const char SectionClose = ']';
        private const char GroupOpen = '{';
        private const char GroupClose = '}';
        private const char EndOfValue = '*';

        private static readonly char[] Equal = new char[] { '=' };

        public Krb5Configuration() { }

        public Krb5Configuration(string configuration)
        {
            Parse(configuration);
        }

        public int IndentWidth { get; set; } = 3;

        private int indent = 0;

        public string Serialize()
        {
            var sb = new StringBuilder();

            foreach (var config in Configuration)
            {
                var section = config.Value as Krb5Configuration;

                SerializeSection(sb, section);
            }

            return sb.ToString();
        }

        private void SerializeSection(StringBuilder sb, Krb5Configuration section)
        {
            sb.AppendFormat("[{0}]", section.Name);
            sb.AppendLine();

            foreach (var config in section.Configuration)
            {
                var val = config.Value;

                SerializeValue(sb, config.Key, val);
            }

            sb.AppendLine();
        }

        private void SerializeValue(StringBuilder sb, string key, object val)
        {
            if (val is SectionList multiVal)
            {
                SerializeValues(sb, key, multiVal);
            }
            else
            {
                Indent(sb);
                sb.AppendFormat("{0} = {1}", key, val);
                sb.AppendLine();
            }
        }

        private void Indent(StringBuilder sb)
        {
            for (var i = 0; i < indent * IndentWidth; i++)
            {
                sb.Append(" ");
            }
        }

        private void SerializeValues(StringBuilder sb, string key, SectionList multiVal)
        {
            Indent(sb);
            sb.AppendFormat("{0} = {{", key);
            sb.AppendLine();

            indent++;

            foreach (var multi in multiVal)
            {
                var val = multi.Value;

                SerializeValue(sb, multi.Key, val);
            }

            indent--;

            Indent(sb);
            sb.AppendLine("}");
        }

        private void Parse(string configuration)
        {
            var reader = new StringReader(configuration);

            while (TryReadLine(reader, out string currentLine))
            {
                if (CanSkip(currentLine))
                {
                    continue;
                }

                while (IsSectionLine(currentLine))
                {
                    var section = new Krb5Configuration();

                    currentLine = ReadSection(currentLine, reader, section);

                    Configuration.Add(new KeyValuePair<string, object>(section.Name, section));
                }
            }
        }

        private static bool IsSectionLine(string currentLine)
        {
            if (string.IsNullOrWhiteSpace(currentLine))
            {
                return false;
            }

            return currentLine[0] == SectionOpen && currentLine[currentLine.Length - 1] == SectionClose;
        }

        private string ReadSection(string currentLine, StringReader reader, Krb5Configuration section)
        {
            section.Name = currentLine.Substring(1, currentLine.Length - 2);

            while (TryReadLine(reader, out currentLine))
            {
                if (CanSkip(currentLine))
                {
                    continue;
                }

                if (currentLine[0] == SectionOpen)
                {
                    break;
                }

                ReadValue(currentLine, reader, section.Configuration);
            }

            return currentLine;
        }

        private void ReadValue(string currentLine, StringReader reader, SectionList section)
        {
            if (currentLine.IndexOf(GroupOpen) >= 0)
            {
                ReadValues(currentLine, reader, section);
            }
            else
            {
                var split = currentLine.Split(Equal, 2);

                if (split.Length == 2)
                {
                    section.Add(new KeyValuePair<string, object>(split[0].Trim(), split[1].Trim()));
                }

                if (currentLine[currentLine.Length - 1] == EndOfValue)
                {
                    // skip future
                }
            }
        }

        private void ReadValues(string currentLine, StringReader reader, SectionList section)
        {
            var split = currentLine.Split(Equal, 2);

            if (split.Length != 2)
            {
                return;
            }

            var config = new SectionList();

            while (TryReadLine(reader, out currentLine))
            {
                if (CanSkip(currentLine))
                {
                    continue;
                }

                if (currentLine[0] == GroupClose)
                {
                    break;
                }

                ReadValue(currentLine, reader, config);
            }

            section.Add(new KeyValuePair<string, object>(split[0].Trim(), config));
        }

        private static bool TryReadLine(StringReader reader, out string currentLine)
        {
            currentLine = reader.ReadLine();

            if (currentLine == null)
            {
                return false;
            }

            currentLine = currentLine.Trim().Trim('\uFEFF', '\u200B');

            return true;
        }

        private bool CanSkip(string trimmed)
        {
            if (trimmed.Length == 0)
            {
                return true;
            }

            switch (trimmed[0])
            {
                case Comment:
                    return true;
            }

            return false;
        }
    }
}
