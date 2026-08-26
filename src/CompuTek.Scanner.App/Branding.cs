using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CompuTek.Scanner.App
{
    internal static class Branding
    {
        internal const string LogoResourceName = "CompuTek.Scanner.Branding.CompuTekLogo.png";

        internal static Image CreateLogoImage()
        {
            Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(LogoResourceName);
            if (stream == null)
                throw new InvalidDataException("The embedded CompuTek logo is missing.");

            using (stream)
            using (Image source = Image.FromStream(stream, true, true))
                return new Bitmap(source);
        }

        internal static Icon CreateWindowIcon()
        {
            using (Image logo = CreateLogoImage())
            using (Bitmap canvas = new Bitmap(64, 64))
            using (Graphics graphics = Graphics.FromImage(canvas))
            {
                graphics.Clear(Color.Transparent);
                graphics.CompositingQuality = CompositingQuality.HighQuality;
                graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                graphics.SmoothingMode = SmoothingMode.HighQuality;
                Rectangle destination = FitInside(logo.Size, new Rectangle(3, 3, 58, 58));
                graphics.DrawImage(logo, destination);

                IntPtr handle = canvas.GetHicon();
                try
                {
                    using (Icon temporary = Icon.FromHandle(handle))
                        return (Icon)temporary.Clone();
                }
                finally
                {
                    DestroyIcon(handle);
                }
            }
        }

        private static Rectangle FitInside(Size source, Rectangle bounds)
        {
            double scale = Math.Min(
                bounds.Width / (double)source.Width,
                bounds.Height / (double)source.Height);
            int width = Math.Max(1, (int)Math.Round(source.Width * scale));
            int height = Math.Max(1, (int)Math.Round(source.Height * scale));
            return new Rectangle(
                bounds.X + (bounds.Width - width) / 2,
                bounds.Y + (bounds.Height - height) / 2,
                width,
                height);
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr handle);
    }
}
