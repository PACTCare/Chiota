using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Android.Content;
using Xamarin.Forms;
using Xamarin.Forms.Platform.Android;
using Xamarin.Forms.PlatformConfiguration;

[assembly: ExportRenderer(typeof(Entry), typeof(Chiota.Droid.Renderer.EntryRenderer))]
namespace Chiota.Droid.Renderer
{
    public class EntryRenderer : Xamarin.Forms.Platform.Android.EntryRenderer
    {
        public EntryRenderer(Context context) : base(context)
        {
        }

        protected override void OnElementChanged(ElementChangedEventArgs<Entry> e)
        {
            base.OnElementChanged(e);

            if (Control == null) return;
            Control.SetBackgroundColor(Android.Graphics.Color.Transparent);
        }
    }
}
