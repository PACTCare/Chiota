using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Android.Content;
using Android.Graphics;
using Android.Widget;
using Xamarin.Forms;
using Xamarin.Forms.Platform.Android;
using Color = Android.Graphics.Color;
using Switch = Xamarin.Forms.Switch;

[assembly: ExportRenderer(typeof(Switch), typeof(Chiota.Droid.Renderer.SwitchRenderer))]
namespace Chiota.Droid.Renderer
{
    public class SwitchRenderer : Xamarin.Forms.Platform.Android.SwitchRenderer
    {
        private Color OnColor;

        public SwitchRenderer(Context context) : base(context)
        {
        }

        protected override void OnElementChanged(ElementChangedEventArgs<Switch> e)
        {
            base.OnElementChanged(e);

            if (Control == null) return;

            OnColor = e.NewElement.OnColor.ToAndroid();

            if (Control.Checked)
                Control.ThumbDrawable.SetColorFilter(OnColor, PorterDuff.Mode.SrcAtop);
            else
                Control.ThumbDrawable.SetColorFilter(Color.White, PorterDuff.Mode.SrcAtop);

            Control.CheckedChange += OnCheckedChange;
        }

        private void OnCheckedChange(object sender, CompoundButton.CheckedChangeEventArgs e)
        {
            if (Control.Checked)
                Control.ThumbDrawable.SetColorFilter(OnColor, PorterDuff.Mode.SrcAtop);
            else
                Control.ThumbDrawable.SetColorFilter(Color.White, PorterDuff.Mode.SrcAtop);
        }
    }
}
