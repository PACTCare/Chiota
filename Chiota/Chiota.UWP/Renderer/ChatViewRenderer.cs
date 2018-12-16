#region References

using System.ComponentModel;
using Chiota.Controls;
using Chiota.UWP.Renderer;
using Xamarin.Forms.Platform.UWP;
using Windows.UI.Xaml.Controls;

#endregion

[assembly: ExportRenderer(typeof(ChatView), typeof(ChatViewRenderer))]
namespace Chiota.UWP.Renderer
{
    public class ChatViewRenderer : ScrollViewRenderer
    {
        protected override void OnElementPropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            base.OnElementPropertyChanged(sender, e);

            Control.HorizontalScrollBarVisibility = ScrollBarVisibility.Hidden;
            Control.VerticalScrollBarVisibility = ScrollBarVisibility.Hidden;
        }
    }
}
