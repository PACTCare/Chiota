using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Threading;

namespace Test
{
    public static class ConsoleUtils
    {
        /// <summary>
        /// Center the console window
        /// </summary>
        public static void CenterConsole()
        {
            IntPtr hWin = GetConsoleWindow();
            RECT rc;
            GetWindowRect(hWin, out rc);
            Screen scr = Screen.FromPoint(new Point(rc.left, rc.top));
            int x = scr.WorkingArea.Left + (scr.WorkingArea.Width - (rc.right - rc.left)) / 2;
            int y = scr.WorkingArea.Top + (scr.WorkingArea.Height - (rc.bottom - rc.top)) / 2;
            MoveWindow(hWin, x, y, rc.right - rc.left, rc.bottom - rc.top, false);
            Thread.Sleep(100);
        }

        /// <summary>
        /// Size the console window
        /// </summary>
        /// 
        /// <param name="Width">Screen width</param>
        /// <param name="Height">Screen height</param>
        public static void SizeConsole(int Width, int Height)
        {
            Console.SetWindowSize(Math.Min(Width, Console.LargestWindowWidth), Math.Min(Height, Console.LargestWindowHeight));
            Thread.Sleep(100);
        }

        private struct RECT { public int left, top, right, bottom; }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT rc);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool MoveWindow(IntPtr hWnd, int x, int y, int w, int h, bool repaint);
    }
}
