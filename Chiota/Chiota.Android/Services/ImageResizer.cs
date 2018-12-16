#region References

using System.IO;
using System.Threading.Tasks;
using Android.Graphics;
using Chiota.Droid.Services;
using Chiota.Services;
using Xamarin.Forms;

#endregion

[assembly: Dependency(typeof(ImageResizer))]
namespace Chiota.Droid.Services
{
    public class ImageResizer : IImageResizer
    {
        public Task<byte[]> Resize(byte[] imageData, float size)
        {
            var task = Task.Run(() => ResizeImage(imageData, size));
            task.Wait();

            return task;
        }

        private byte[] ResizeImage(byte[] imageData, float size)
        {
            // Load the bitmap
            var originalImage = BitmapFactory.DecodeByteArray(imageData, 0, imageData.Length);

            var originHeight = originalImage.Height;
            var originWidth = originalImage.Width;

            float newHeight = 0;
            float newWidth = 0;
            float value = 0;

            if (originHeight > originWidth)
            {
                value = 1 / (originWidth / size);

                newWidth = size;
                newHeight = originHeight * value;
            }
            else if (originHeight < originWidth)
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

            var resizedImage = Bitmap.CreateScaledBitmap(originalImage, (int)newWidth, (int)newHeight, false);

            using (var ms = new MemoryStream())
            {
                resizedImage.Compress(Bitmap.CompressFormat.Jpeg, 100, ms);
                return ms.ToArray();
            }
        }
    }
}