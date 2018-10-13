using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;
using Windows.UI.Xaml.Media.Imaging;
using Chiota.Services;
using Chiota.UWP.Services;
using Xamarin.Forms;
using ZXing;
using ZXing.Common;

[assembly: Dependency(typeof(ImageQrCodeReader))]
namespace Chiota.UWP.Services
{
    public class ImageQrCodeReader : IImageQrCodeReader
    {
        public async Task<string> ReadAsync(byte[] data)
        {
            return await ReadImageAsync(data);
        }

        private async Task<string> ReadImageAsync(byte[] data)
        {
            try
            {
                var bitmap = new BitmapImage();
                using (var stream = new InMemoryRandomAccessStream())
                {
                    await stream.WriteAsync(data.AsBuffer());
                    stream.Seek(0);
                    await bitmap.SetSourceAsync(stream);
                }

                var source = new RGBLuminanceSource(data, bitmap.PixelWidth, bitmap.PixelHeight);
                var reader = new ZXing.QrCode.QRCodeReader();
                var binarizer = new HybridBinarizer(source);
                var bitmapx = new BinaryBitmap(binarizer);
                var result = reader.decode(bitmapx);

                return result.Text;
            }
            catch (Exception ex)
            {
                return string.Empty;
            }
        }
    }
}
