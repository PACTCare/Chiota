#region References

using System;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;
using Windows.UI.Xaml.Media.Imaging;
using Chiota.Services;
using Chiota.UWP.Services;
using Xamarin.Forms;

#endregion

[assembly: Dependency(typeof(ImageResizer))]
namespace Chiota.UWP.Services
{
    public class ImageResizer : IImageResizer
    {
        public async Task<byte[]> Resize(byte[] imageData, float size)
        {
            return await ResizeImage(imageData, size);
        }

        private async Task<byte[]> ResizeImage(byte[] imageData, float size)
        {
            var bitmap = new BitmapImage();
            using (var stream = new InMemoryRandomAccessStream())
            {
                await stream.WriteAsync(imageData.AsBuffer());
                stream.Seek(0);
                await bitmap.SetSourceAsync(stream);
            }

            var originHeight = bitmap.PixelHeight;
            var originWidth = bitmap.PixelWidth;

            float newHeight = 0;
            float newWidth = 0;
            float value = 0;

            if (originHeight > originWidth)
            {
                value = 1 / (originWidth / size);

                newWidth = size;
                newHeight = originHeight * value;
            }
            else if(originHeight < originWidth)
            {
                value = 1 / (originHeight / size);

                newHeight = size;
                newWidth = originWidth * value;
            }
            else
            {
                newHeight = size;
                newWidth = size;
            }

            byte[] resizedData;

            using (var streamIn = new MemoryStream(imageData))
            {
                using (var imageStream = streamIn.AsRandomAccessStream())
                {
                    var decoder = await BitmapDecoder.CreateAsync(imageStream);
                    var resizedStream = new InMemoryRandomAccessStream();
                    var encoder = await BitmapEncoder.CreateForTranscodingAsync(resizedStream, decoder);
                    encoder.BitmapTransform.InterpolationMode = BitmapInterpolationMode.Linear;
                    encoder.BitmapTransform.ScaledHeight = (uint)newHeight;
                    encoder.BitmapTransform.ScaledWidth = (uint)newWidth;
                    await encoder.FlushAsync();
                    resizedStream.Seek(0);
                    resizedData = new byte[resizedStream.Size];
                    await resizedStream.ReadAsync(resizedData.AsBuffer(), (uint)resizedStream.Size, InputStreamOptions.None);
                }
            }

            return resizedData;
        }
    }
}
