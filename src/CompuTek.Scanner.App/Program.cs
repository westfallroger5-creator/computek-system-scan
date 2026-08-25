using System;
using System.Windows.Forms;

namespace CompuTek.Scanner.App
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += delegate(object sender, System.Threading.ThreadExceptionEventArgs args)
            {
                MessageBox.Show(
                    "The scanner application encountered an unexpected error.\r\n\r\n" + args.Exception.Message,
                    "CompuTek Scanner",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            };
            Application.Run(new MainForm());
        }
    }
}
