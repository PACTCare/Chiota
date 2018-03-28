namespace Chiota.Services
{
  public interface IClipboardService
  {
    string GetTextFromClipboard();

    void SendTextToClipboard(string text);
  }
}