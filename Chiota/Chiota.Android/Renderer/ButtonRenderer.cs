#region References

using Android.Content;
using Xamarin.Forms;
using Xamarin.Forms.Platform.Android;
using TextAlignment = Android.Views.TextAlignment;

#endregion

[assembly: ExportRenderer(typeof(Button), typeof(Chiota.Droid.Renderer.ButtonRenderer))]
namespace Chiota.Droid.Renderer
{
    public class ButtonRenderer : Xamarin.Forms.Platform.Android.ButtonRenderer
    {
        public ButtonRenderer(Context context) : base(context)
        {
        }

        protected override void OnElementChanged(ElementChangedEventArgs<Button> e)
        {
            base.OnElementChanged(e);

            Control.SetPadding(0, 0, 0, 0);
            Control.TextAlignment = TextAlignment.Center;
        }
    }
}