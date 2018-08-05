using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Forms;
using Xamarin.Forms.Platform.UWP;

[assembly: ExportRenderer(typeof(Switch), typeof(Chiota.UWP.Renderer.SwitchRenderer))]
namespace Chiota.UWP.Renderer
{
    public class SwitchRenderer : Xamarin.Forms.Platform.UWP.SwitchRenderer
    {
        protected override void OnElementChanged(ElementChangedEventArgs<Switch> e)
        {
            base.OnElementChanged(e);

            if (Control == null) return;
            Control.OnContent = "";
            Control.OffContent = "";
        }
    }
}
