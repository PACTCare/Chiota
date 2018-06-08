namespace Chiota.UWP.Services
{
  using System;
  using System.IO;
  using System.Runtime.InteropServices.WindowsRuntime;
  using System.Threading.Tasks;

  using Chiota.Services;

  using Windows.Graphics.Imaging;
  using Windows.Storage.Streams;

  public class ResizeService : IResizeService
  {
    public async Task<byte[]> ResizeImage(byte[] imageData, float width, float height)
    {
      byte[] resizedData;

      using (var streamIn = new MemoryStream(imageData))
      {
        using (var imageStream = streamIn.AsRandomAccessStream())
        {
          var decoder = await BitmapDecoder.CreateAsync(imageStream);
          var resizedStream = new InMemoryRandomAccessStream();

          float originalHeight = decoder.PixelHeight;
          float originalWidth = decoder.PixelWidth;

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

          var encoder = await BitmapEncoder.CreateForTranscodingAsync(resizedStream, decoder);
          encoder.BitmapTransform.InterpolationMode = BitmapInterpolationMode.Linear;
          encoder.BitmapTransform.ScaledHeight = (uint)height;
          encoder.BitmapTransform.ScaledWidth = (uint)width;
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
