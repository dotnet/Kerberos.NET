using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace KerbDump
{
    public partial class MessageTreeView : UserControl
    {
        private readonly Font DefaultTreeFont;

        public MessageTreeView()
        {
            InitializeComponent();

            this.DefaultTreeFont = new Font(
                this.tree.Font.FontFamily,
                this.tree.Font.Size,
                FontStyle.Italic
            );
        }

        public void Reset()
        {
            this.tree.Nodes.Clear();
        }

        public void RenderObject(object obj, string label)
        {
            var json = FormatSerialize(obj);

            if (string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            this.tree.BeginUpdate();

            this.tree.Nodes.Clear();

            using (var reader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var jt = JToken.Load(jsonReader);

                var root = new TreeNode(label);

                this.AddNode(jt, root);

                this.tree.Nodes.Add(root);

                this.tree.ExpandAll();
            }

            if (this.tree.Nodes.Count > 0)
            {
                this.tree.Nodes[0].EnsureVisible();
                this.tree.Nodes[0].NodeFont = new Font(this.tree.Font, FontStyle.Regular);
            }

            this.tree.EndUpdate();
        }

        private TreeNode MakeNode(string display)
        {
            var node = new TreeNode(display);

            node.ContextMenuStrip = new ContextMenuStrip { Tag = node };

            if (display.IndexOf(" = ") > 0)
            {
                node.ContextMenuStrip.Items.Add("Copy", null, this.CopyNodeText);
            }

            node.ContextMenuStrip.Items.Add("Copy Value", null, this.CopyNodeValue);

            return node;
        }

        private int AddNode(JToken token, TreeNode inTreeNode)
        {
            if (token == null)
            {
                return 0;
            }

            if (token.Path.Split('.').Length == 1)
            {
                inTreeNode.NodeFont = new Font(this.DefaultTreeFont, FontStyle.Bold);
            }

            if (token is JValue)
            {
                inTreeNode.Nodes.Add(this.MakeNode(token.ToString()));

                return 0;
            }
            else if (token is JObject obj)
            {
                int children = 0;

                foreach (var property in obj.Properties())
                {
                    children++;

                    if (property.Value is JValue)
                    {
                        var childNode = this.MakeNode($"{property.Name} = {property.Value}");

                        if (string.IsNullOrWhiteSpace(property.Value.ToString()))
                        {
                            childNode.NodeFont = this.DefaultTreeFont;
                        }

                        inTreeNode.Nodes.Add(childNode);
                    }
                    else
                    {
                        var childNode = this.MakeNode(property.Name);

                        var childrenAdded = this.AddNode(property.Value, childNode);

                        inTreeNode.Nodes.Add(childNode);

                        if (childrenAdded == 0)
                        {
                            childNode.NodeFont = this.DefaultTreeFont;
                        }
                    }
                }

                return children;
            }
            else if (token is JArray array)
            {
                for (int i = 0; i < array.Count; i++)
                {
                    var value = array[i];

                    if (value.Type == JTokenType.String)
                    {
                        if (array.Count == 1)
                        {
                            inTreeNode.Text += $" = {value}";
                        }
                        else
                        {
                            this.AddNode(value, inTreeNode);
                        }
                    }
                    else
                    {
                        var typeNames = new[] { "Type", "Mechanism", "Value" };

                        string typeName = null;

                        foreach (var type in typeNames)
                        {
                            if (TryExtractPropertyForName(value, type, out typeName))
                            {
                                break;
                            }
                        }

                        if (string.IsNullOrWhiteSpace(typeName))
                        {
                            typeName = i.ToString();
                        }

                        var childNode = inTreeNode.Nodes[inTreeNode.Nodes.Add(this.MakeNode(typeName))];

                        this.AddNode(value, childNode);
                    }
                }

                return array.Count;
            }

            return 0;
        }

        private static bool TryExtractPropertyForName(JToken value, string type, out string typeName)
        {
            typeName = null;

            if (value is JObject valueObj &&
                valueObj.TryGetValue(type, out JToken typeProp))
            {
                typeName = typeProp.ToString();

                valueObj.Remove(type);

                return true;
            }

            return false;
        }

        private void CopyNodeValue(object sender, EventArgs e)
        {
            if (sender is ToolStripMenuItem item &&
                item.GetCurrentParent() is ToolStrip menu)
            {
                if (menu.Tag is TreeNode node)
                {
                    string text = StripEquals(node);

                    Clipboard.SetText(text);
                }
                else if (menu.Tag is TreeView tree)
                {
                    string text = StripEquals(tree.SelectedNode);

                    Clipboard.SetText(text);
                }
            }
        }

        private void CopyNodeText(object sender, EventArgs e)
        {
            if (sender is ToolStripMenuItem item &&
                item.GetCurrentParent() is ToolStrip menu)
            {
                if (menu.Tag is TreeNode node)
                {
                    Clipboard.SetText(node.Text);
                }
                else if (menu.Tag is TreeView tree)
                {
                    Clipboard.SetText(tree.SelectedNode?.Text);
                }
            }
        }

        private static string StripEquals(TreeNode node)
        {
            if (string.IsNullOrWhiteSpace(node?.Text))
            {
                return null;
            }

            var text = node.Text;

            var index = text.IndexOf('=');

            if (index > 0)
            {
                text = text.Substring(index + 1);
            }

            return text.Trim();
        }

        private string FormatSerialize(object obj)
        {
            var settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                Converters = new JsonConverter[] { new StringEnumArrayConverter(), new BinaryConverter(), new PacConverter() },
                ContractResolver = new KerberosIgnoreResolver()
            };

            return JsonConvert.SerializeObject(obj, settings);
        }

        private class PacConverter : JsonConverter
        {
            public override bool CanConvert(Type objectType)
            {
                return objectType == typeof(RpcFileTime) ||
                       objectType == typeof(RpcString) ||
                       objectType == typeof(RpcSid);
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                throw new NotImplementedException();
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                if (value.GetType() == typeof(RpcFileTime))
                {
                    var rpc = (RpcFileTime)value;
                    var dt = (DateTimeOffset)rpc;

                    var dtConverter = new IsoDateTimeConverter();

                    dtConverter.WriteJson(writer, dt, serializer);
                }
                else if (value.GetType() == typeof(RpcString))
                {
                    writer.WriteValue(value?.ToString());
                }
                else if (value.GetType() == typeof(RpcSid))
                {
                    var rpcSid = (RpcSid)value;

                    writer.WriteValue(rpcSid.ToSecurityIdentifier().Value);
                }
            }
        }

        private class BinaryConverter : JsonConverter
        {
            public override bool CanConvert(Type objectType)
            {
                Debug.WriteLine(objectType.Name);

                return objectType == typeof(ReadOnlyMemory<byte>) ||
                       objectType == typeof(ReadOnlyMemory<byte>?) ||
                       objectType == typeof(ReadOnlySequence<byte>) ||
                       objectType == typeof(ReadOnlyMemory<int>) ||
                       objectType == typeof(Memory<byte>);
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                throw new NotImplementedException();
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                Reflect.IsBytes(value, out ReadOnlyMemory<byte> mem);

                writer.WriteStartObject();
                writer.WritePropertyName("Length");
                writer.WriteValue(mem.Length);
                writer.WritePropertyName("Value");
                writer.WriteValue(Convert.ToBase64String(mem.ToArray()));
                writer.WriteEndObject();
            }
        }

        private class StringEnumArrayConverter : StringEnumConverter
        {
            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                if (value == null)
                {
                    writer.WriteNull();
                    return;
                }

                Enum e = (Enum)value;

                var enumVal = e.ToString().Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries);

                if (enumVal.Length == 0)
                {
                    writer.WriteNull();
                }
                else if (enumVal.Length == 1)
                {
                    writer.WriteValue(enumVal.First());
                }
                else
                {
                    writer.WriteStartArray();

                    foreach (var en in enumVal)
                    {
                        writer.WriteValue(en);
                    }

                    writer.WriteEndArray();
                }
            }
        }
    }
}
