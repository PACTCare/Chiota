using System;
using System.Threading.Tasks;
using Android.Graphics;
using Chiota.Droid.Services;
using Chiota.Services;
using Xamarin.Forms;
using ZXing;
using ZXing.Common;

[assembly: Dependency(typeof(ImageQrCodeReader))]
namespace Chiota.Droid.Services
{
    public class ImageQrCodeReader : IImageQrCodeReader
    {
        public Task<string> ReadAsync(byte[] data)
        {
            var task = Task.Run(() => ReadImageAsync(data));
            task.Wait();

            return task;
        }

        private string ReadImageAsync(byte[] data)
        {
            try
            {
                var originalImage = BitmapFactory.DecodeByteArray(data, 0, data.Length);

                var source = new RGBLuminanceSource(data, originalImage.Width, originalImage.Height);
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
