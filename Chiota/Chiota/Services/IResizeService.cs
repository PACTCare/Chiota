namespace Chiota.Services
{
  using System.Threading.Tasks;

  // https://forums.xamarin.com/discussion/comment/199212#Comment_199212
  // https://github.com/xamarin/xamarin-forms-samples/blob/master/XamFormsImageResize/XamFormsImageResize/ImageResizer.cs
  public interface IResizeService
  {
    Task<byte[]> ResizeImage(byte[] imageData, float width, float height);
  }
}
