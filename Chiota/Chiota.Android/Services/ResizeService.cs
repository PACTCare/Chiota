namespace Chiota.Droid.Services
{
  using System.IO;
  using System.Threading.Tasks;

  using Android.Graphics;

  using Chiota.Services;

  public class ResizeService : IResizeService
  {
    public async Task<byte[]> ResizeImage(byte[] imageData, float width, float height)
    {
      var options =
        new BitmapFactory.Options
          {
            InPurgeable = true
          }; // Create object of bitmapfactory's option method for further option use
      // inPurgeable is used to free up memory while required
      // Load the bitmap
      var originalImage = await BitmapFactory.DecodeByteArrayAsync(imageData, 0, imageData.Length);

      var originalHeight = originalImage.Height;
      var originalWidth = originalImage.Width;

      if (originalWidth < width && height > originalHeight)
      {
        return imageData;
      }

      if (originalHeight > originalWidth)
      {
        var ratio = originalHeight / height;
        width = originalWidth / ratio;
      }
      else 
      {
        var ratio = originalWidth / width;
        height = originalHeight / ratio;
      }

      var resizedImage = Bitmap.CreateScaledBitmap(originalImage, (int)width, (int)height, false);
      
      originalImage.Recycle();
      
      using (var ms = new MemoryStream())
      {
        resizedImage.Compress(Bitmap.CompressFormat.Png, 100, ms);
        return ms.ToArray();
      }
    }
  }
}