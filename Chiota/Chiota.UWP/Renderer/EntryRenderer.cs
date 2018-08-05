using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.UI.Xaml;
using Xamarin.Forms;
using Xamarin.Forms.Platform.UWP;
using Point = Windows.Foundation.Point;
using TextAlignment = Windows.UI.Xaml.TextAlignment;

[assembly: ExportRenderer(typeof(Entry), typeof(Chiota.UWP.Renderer.EntryRenderer))]
namespace Chiota.UWP.Renderer
{
    public class EntryRenderer : Xamarin.Forms.Platform.UWP.EntryRenderer
    {
        protected override void OnElementChanged(ElementChangedEventArgs<Entry> e)
        {
            base.OnElementChanged(e);

            if (Control == null) return;
            Control.BorderThickness = new Windows.UI.Xaml.Thickness(0);
            Control.VerticalAlignment = VerticalAlignment.Center;
        }
    }
}
