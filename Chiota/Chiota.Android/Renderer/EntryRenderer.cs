#region References

using Android.Content;
using Xamarin.Forms;
using Xamarin.Forms.Platform.Android;

#endregion

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
