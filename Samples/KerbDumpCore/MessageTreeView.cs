using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security;
using System.Windows.Forms;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;

namespace KerbDump
{
    public partial class MessageTreeView : UserControl
    {
        private static readonly JsonSerializerSettings SerializerSettings = new()
        {
            Formatting = Formatting.Indented,
            Converters = new JsonConverter[] { new StringEnumArrayConverter(), new BinaryConverter(), new PacConverter() },
            ContractResolver = new KerberosIgnoreResolver()
        };

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

        private KeyTable keytab;

        public void RenderObject(object obj, string label, KeyTable key)
        {
            this.keytab = key;

            var json = FormatSerialize(obj);

            if (string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            this.tree.BeginUpdate();

            this.tree.Nodes.Clear();

            CreateTreeRoot(label, json, this.tree.TopNode);

            if (this.tree.Nodes.Count > 0)
            {
                this.tree.Nodes[0].EnsureVisible();
                this.tree.Nodes[0].NodeFont = new Font(this.tree.Font, FontStyle.Regular);
            }

            this.tree.EndUpdate();
        }

        private void CreateTreeRoot(string label, string json, TreeNode top)
        {
            using (var reader = new StringReader(json))
            using (var jsonReader = new JsonTextReader(reader))
            {
                var jt = JToken.Load(jsonReader);

                var root = new TreeNode(label);

                this.AddRoot(jt, root, top);

                this.tree.ExpandAll();
            }
        }

        private void AddRoot(JToken jt, TreeNode root, TreeNode top)
        {
            this.AddNode(jt, root);

            if (top != null)
            {
                top.Nodes.Add(root);
            }
            else
            {
                this.tree.Nodes.Add(root);
            }
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

            node.ContextMenuStrip.Items.Add(new ToolStripMenuItem("Decode As...", null, new[]
            {
                new ToolStripMenuItem("AP-REQ", null, OnClickDecodeAsApReq),
                new ToolStripMenuItem("Ad-If-Relevant", null, OnClickDecodeAsAdIfRelevant),
                new ToolStripMenuItem("Ad-Win2k-Pac", null, OnClickDecodeAsAdWin2kPac),
            }));

            return node;
        }

        private static void ParseNode(object sender, out string text, out TreeNode parentNode)
        {
            text = null;
            parentNode = null;

            if (sender is ToolStripItem item &&
                item.OwnerItem is ToolStripItem parentItem &&
                parentItem.Owner is ContextMenuStrip menu)
            {
                if (menu.Tag is TreeNode node)
                {
                    parentNode = node;
                    text = node.Text;
                }
                else if (menu.Tag is TreeView tree)
                {
                    text = tree.SelectedNode?.Text;
                    parentNode = tree.SelectedNode;
                }
            }

            if (!string.IsNullOrWhiteSpace(text))
            {
                foreach (var prefix in LabelPrefixes)
                {
                    if (text.StartsWith(prefix))
                    {
                        text = text[prefix.Length..];
                        break;
                    }
                }
            }
        }

        private static readonly IEnumerable<string> LabelPrefixes = new[]
        {
            "Data = ",
            "Value = ",
            "Cipher = "
        };

        private void OnClickDecodeAsAdWin2kPac(object sender, EventArgs e)
        {
            ParseNode(sender, out string text, out TreeNode parentNode);

            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    DecodeAsAdWin2kPac(Convert.FromBase64String(text), parentNode);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"DecodeAsAdWin2kPac exception: {ex}");
                }
            }
        }

        private void OnClickDecodeAsAdIfRelevant(object sender, EventArgs e)
        {
            ParseNode(sender, out string text, out TreeNode parentNode);

            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    DecodeAsAdIfRelevant(Convert.FromBase64String(text), parentNode);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"DecodeAsAdIfRelevant exception: {ex}");
                }
            }
        }

        private void DecodeAsAdWin2kPac(byte[] bytes, TreeNode parentNode)
        {
            var pac = new PrivilegedAttributeCertificate(new KrbAuthorizationData { Data = bytes, Type = AuthorizationDataType.AdWin2kPac });

            ExplodeObject(pac, "Privilege Attribute Certificate", parentNode);
        }

        private void ExplodeObject(object thing, string label, TreeNode parentNode)
        {
            var serialized = FormatSerialize(thing);

            this.CreateTreeRoot(label, serialized, parentNode);

            parentNode.ExpandAll();
        }

        private void DecodeAsAdIfRelevant(byte[] bytes, TreeNode parentNode)
        {
            var seq = KrbAuthorizationDataSequence.Decode(bytes);

            foreach (var authz in seq.AuthorizationData)
            {
                ExplodeObject(authz, "AuthorizationData", parentNode);
            }
        }

        private void OnClickDecodeAsApReq(object sender, EventArgs e)
        {
            ParseNode(sender, out string text, out TreeNode parentNode);

            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    DecodeAsApReq(Convert.FromBase64String(text), parentNode);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"DecodeAsApReq exception: {ex}");
                }
            }
        }

        private void DecodeAsApReq(byte[] bytes, TreeNode parentNode)
        {
            var apReq = KrbApReq.DecodeApplication(bytes);

            ExplodeObject(apReq, "AP-REQ", parentNode);
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

                ConfigureDecryption(inTreeNode, token, token.Path);

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

        private void ConfigureDecryption(TreeNode inTreeNode, JToken token, string scope)
        {
            if (!EncryptedFields.Keys.Any(s => string.Equals(s, scope, StringComparison.InvariantCultureIgnoreCase)))
            {
                return;
            }

            var decryptMenuItems = new List<ToolStripItem>();

            foreach (KeyUsage k in Enum.GetValues(typeof(KeyUsage)))
            {
                decryptMenuItems.Add(new ToolStripMenuItem($"({(int)k}) {k}", null, DecryptMessageWithKeyUsage) { Tag = k });
            }

            inTreeNode.ContextMenuStrip ??= new() { Tag = inTreeNode };

            if (inTreeNode.ContextMenuStrip.Items.Count > 0)
            {
                inTreeNode.ContextMenuStrip.Items.Add("-");
            }

            inTreeNode.ContextMenuStrip.Items.Add(new ToolStripMenuItem("Decrypt", null, DecryptMessage) { Tag = token, Name = scope });

            inTreeNode.ContextMenuStrip.Items.Add(new ToolStripMenuItem("Decrypt With...", null, decryptMenuItems.ToArray()));
        }

        private void DecryptMessage(object sender, EventArgs e)
        {
            if (sender is ToolStripItem item && item.Tag is JToken)
            {
                Decrypt(item);
            }
        }

        private void DecryptMessageWithKeyUsage(object sender, EventArgs e)
        {
            if (sender is ToolStripItem item && item.Tag is KeyUsage usage && item.OwnerItem is ToolStripItem parentItem)
            {
                Decrypt(parentItem, usage);
            }
        }

        private void Decrypt(object sender, KeyUsage? usage = null)
        {
            if (sender is ToolStripItem item && item.Tag is JToken token)
            {
                try
                {
                    PopAndDecrypt(token, item, usage);
                }
                catch (SecurityException ex)
                {
                    MessageBox.Show($"Decryption failed: {ex.Message}", "Couldn't decrypt the message", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Something else failed: {ex.Message}", "Couldn't decrypt the message", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private static readonly Dictionary<string, (KeyUsage usage, Func<ReadOnlyMemory<byte>, object> decoder)> EncryptedFields
            = new()
            {
                { "KrbApReq.Ticket.EncryptedPart", (KeyUsage.Ticket, b => KrbEncTicketPart.DecodeApplication(b)) },
                { "KrbApReq.Authenticator", (KeyUsage.ApReqAuthenticator, b => KrbAuthenticator.DecodeApplication(b)) },
                { "Ticket.EncryptedPart", (KeyUsage.Ticket, b => KrbEncTicketPart.DecodeApplication(b)) },
                { "Body.EncAuthorizationData", (KeyUsage.Ticket, b => KrbEncTicketPart.DecodeApplication(b)) },
            };

        private void PopAndDecrypt(JToken token, ToolStripItem item, KeyUsage? usage)
        {
            if (!EncryptedFields.TryGetValue(item.Name, out (KeyUsage usage, Func<ReadOnlyMemory<byte>, object> decoder) decoder))
            {
                return;
            }

            if (this.keytab == null)
            {
                return;
            }

            var serializer = new JsonSerializer() { ContractResolver = SerializerSettings.ContractResolver };

            foreach (var conv in SerializerSettings.Converters)
            {
                serializer.Converters.Add(conv);
            }

            var encryptedData = token.ToObject<KrbEncryptedData>(serializer);

            object decrypted = null;

            try
            {
                var key = this.keytab.GetKey(encryptedData.EType, null);

                decrypted = encryptedData.Decrypt(key, usage ?? decoder.usage, decoder.decoder);
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }

            if (decrypted == null)
            {
                throw new SecurityException($"The provided key couldn't decrypt the message as either a password or as the derived key");
            }

            var serialized = FormatSerialize(decrypted);

            var node = item.OwnerItem?.Tag as TreeNode ?? item.Owner?.Tag as TreeNode;

            this.CreateTreeRoot(item.Name, serialized, node);

            node.ExpandAll();
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

        private static string FormatSerialize(object obj)
        {
            return JsonConvert.SerializeObject(obj, SerializerSettings);
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
                if (objectType == typeof(ReadOnlyMemory<byte>) && reader.Value != null)
                {
                    ReadOnlyMemory<byte> val = Convert.FromBase64String(reader.Value as string);

                    return val;
                }

                if (objectType == typeof(ReadOnlyMemory<byte>?) && reader.Value != null)
                {
                    ReadOnlyMemory<byte> val = Convert.FromBase64String(reader.Value as string);

                    return val;
                }

                return null;
            }

            public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
            {
                ReadOnlyMemory<byte> mem = default;

                if (value.GetType() == typeof(ReadOnlyMemory<byte>))
                {
                    mem = (ReadOnlyMemory<byte>)value;
                }
                else if (value.GetType() == typeof(ReadOnlyMemory<byte>?))
                {
                    var val = (ReadOnlyMemory<byte>?)value;

                    if (val != null)
                    {
                        mem = val.Value;
                    }
                }

                writer.WriteValue(Convert.ToBase64String(mem.ToArray()));
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
