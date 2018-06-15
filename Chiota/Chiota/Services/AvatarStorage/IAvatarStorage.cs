namespace Chiota.Services.AvatarStorage
{
  using System.Threading.Tasks;

  public interface IAvatarStorage
  {
    Task<string> UploadAsync(string imageName, string path, byte[] imageAsBytes);
  }
}
