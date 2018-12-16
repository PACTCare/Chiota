#region References

using System;
using System.IO;
using System.Threading.Tasks;
using Android.App;
using Android.Graphics;
using Chiota.Droid.Services;
using Chiota.Services;
using Plugin.CurrentActivity;
using Xamarin.Forms;

#endregion

[assembly: Dependency(typeof(Screenshot))]
namespace Chiota.Droid.Services
{
    public class Screenshot : IScreenshot
    {
        private Activity Context =>
            CrossCurrentActivity.Current.Activity ?? throw new NullReferenceException("Current Context/Activity is null, ensure that the MainApplication.cs file is setting the CurrentActivity in your source code so the Screenshot can use it.");

        public async Task<string> CaptureAndSaveAsync()
        {
            var bytes = await CaptureAsync();
            Java.IO.File picturesFolder = Android.OS.Environment.GetExternalStoragePublicDirectory(Android.OS.Environment.DirectoryPictures);
            string date = DateTime.Now.ToString().Replace("/", "-").Replace(":", "-");
            try
            {
                string filePath = System.IO.Path.Combine(picturesFolder.AbsolutePath, "Screnshot-" + date + ".png");
                using (System.IO.FileStream SourceStream = System.IO.File.Open(filePath, System.IO.FileMode.OpenOrCreate))
                {
                    SourceStream.Seek(0, System.IO.SeekOrigin.End);
                    await SourceStream.WriteAsync(bytes, 0, bytes.Length);
                }
                return filePath;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public async System.Threading.Tasks.Task<byte[]> CaptureAsync()
        {
            await Task.Delay(1000);
            if (Context == null)
            {
                throw new Exception("You have to set Screenshot.Activity in your Android project");
            }
            var view = Context.Window.DecorView;
            view.DrawingCacheEnabled = true;

            Bitmap bitmap = view.GetDrawingCache(true);

            byte[] bitmapData;

            using (var stream = new MemoryStream())
            {
                bitmap.Compress(Bitmap.CompressFormat.Png, 0, stream);
                bitmapData = stream.ToArray();
            }

            return bitmapData;
        }
    }
}
