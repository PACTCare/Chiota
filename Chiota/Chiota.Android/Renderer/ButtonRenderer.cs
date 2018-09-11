using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Xamarin.Forms;
using Xamarin.Forms.Platform.Android;
using TextAlignment = Android.Views.TextAlignment;

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