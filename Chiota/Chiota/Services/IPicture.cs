namespace Chiota.Services
{
  public interface IPicture
  {
    void SavePictureToDisk(string filename, byte[] imageData);
  }
}
