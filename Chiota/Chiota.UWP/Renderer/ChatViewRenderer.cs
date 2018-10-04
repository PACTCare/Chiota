using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chiota.Controls;
using Chiota.UWP.Renderer;
using Xamarin.Forms.Platform.UWP;
using Windows.UI.Xaml.Controls;

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
