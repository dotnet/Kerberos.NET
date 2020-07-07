namespace Fiddler.Kerberos.NET
{
    partial class KerberosMessageView
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.tvMessageStructure = new System.Windows.Forms.TreeView();
            this.SuspendLayout();
            // 
            // tvMessageStructure
            // 
            this.tvMessageStructure.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tvMessageStructure.Location = new System.Drawing.Point(0, 0);
            this.tvMessageStructure.Name = "tvMessageStructure";
            this.tvMessageStructure.Size = new System.Drawing.Size(852, 491);
            this.tvMessageStructure.TabIndex = 0;
            // 
            // KerberosMessageView
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.tvMessageStructure);
            this.Name = "KerberosMessageView";
            this.Size = new System.Drawing.Size(852, 491);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TreeView tvMessageStructure;
    }
}
