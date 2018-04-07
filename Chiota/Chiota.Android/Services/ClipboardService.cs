using Xamarin.Forms;

[assembly: Dependency(typeof(Chiota.Droid.ClipboardService))]

namespace Chiota.Droid
{
  using Android.Content;

  using Chiota.Services;

  using Xamarin.Forms;

  public class ClipboardService : IClipboardService
  {
    public string GetTextFromClipboard()
    {
      var clipboardmanager = (ClipboardManager)Forms.Context.GetSystemService(Context.ClipboardService);
      var item = clipboardmanager.PrimaryClip.GetItemAt(0);
      var text = item.Text;
      return text;
    }

    public void SendTextToClipboard(string text)
    {
      // Get the Clipboard Manager
      var clipboardManager = (ClipboardManager)Forms.Context.GetSystemService(Context.ClipboardService);

      // Create a new Clip
      var clip = ClipData.NewPlainText("Address copied to clipboard", text);

      // Copy the text
      clipboardManager.PrimaryClip = clip;
    }
  }
}