#region References

using System;
using System.IO;
using System.Threading.Tasks;
using Windows.Graphics.Display;
using Windows.Graphics.Imaging;
using Windows.Security.Cryptography;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Media.Imaging;
using Chiota.Services;
using Chiota.UWP.Services;
using Xamarin.Forms;

#endregion

[assembly: Dependency(typeof(Screenshot))]
namespace Chiota.UWP.Services
{
    public class Screenshot : IScreenshot
    {
        public async Task<string> CaptureAndSaveAsync()
        {
            var bytes = await CaptureAsync();
            var picturesLibrary = KnownFolders.PicturesLibrary;
            var savedPicturesFolder = await picturesLibrary.CreateFolderAsync("Screenshots", CreationCollisionOption.OpenIfExists);
            var date = DateTime.Now.ToString().Replace("/", "-").Replace(":", "-");
            try
            {
                StorageFile imageFile = await savedPicturesFolder.CreateFileAsync("Screenshot-" + date + ".png", CreationCollisionOption.ReplaceExisting);
                using (System.IO.Stream SourceStream = await imageFile.OpenStreamForWriteAsync())
                {
                    SourceStream.Seek(0, System.IO.SeekOrigin.End);
                    await SourceStream.WriteAsync(bytes, 0, bytes.Length);
                }
                return imageFile.Path;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public async Task<byte[]> CaptureAsync()
        {
            await Task.Delay(1000);
            var rtb = new RenderTargetBitmap();
            await rtb.RenderAsync(Window.Current.Content);

            var pixelBuffer = await rtb.GetPixelsAsync();
            byte[] pixels;
            CryptographicBuffer.CopyToByteArray(pixelBuffer, out pixels);

            // Useful for rendering in the correct DPI
            var displayInformation = DisplayInformation.GetForCurrentView();

            var stream = new InMemoryRandomAccessStream();
            var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.JpegEncoderId, stream);
            encoder.SetPixelData(BitmapPixelFormat.Bgra8,
            BitmapAlphaMode.Premultiplied,
            (uint)rtb.PixelWidth,
            (uint)rtb.PixelHeight,
            displayInformation.RawDpiX,
            displayInformation.RawDpiY,
            pixels);

            await encoder.FlushAsync();
            stream.Seek(0);

            var readStram = stream.AsStreamForRead();
            var bytes = new byte[readStram.Length];
            readStram.Read(bytes, 0, bytes.Length);

            return bytes;
        }
    }
}
