using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Media;
using Xamarin.Forms;
using Xamarin.Forms.Platform.UWP;

[assembly: ExportRenderer(typeof(Xamarin.Forms.Frame), typeof(Chiota.UWP.Renderer.FrameRenderer))]
namespace Chiota.UWP.Renderer
{
    public class FrameRenderer : Xamarin.Forms.Platform.UWP.FrameRenderer
    {
        protected override void OnElementChanged(ElementChangedEventArgs<Frame> e)
        {
            base.OnElementChanged(e);

            if (Control == null || e.NewElement == null || e.NewElement.CornerRadius <= 0) return;

            var frame = e.NewElement;
            var frameBrush = Windows.UI.Color.FromArgb(
                (byte)(frame.BackgroundColor.A * 255),
                (byte)(frame.BackgroundColor.R * 255),
                (byte)(frame.BackgroundColor.G * 255),
                (byte)(frame.BackgroundColor.B * 255));

            Control.CornerRadius = new CornerRadius(frame.CornerRadius);

            Control.Background = new SolidColorBrush(frameBrush);
            frame.BackgroundColor = Color.Transparent;
        }
    }
}
