using System.ComponentModel;
using Android.Content;
using Xamarin.Forms;
using Xamarin.Forms.Platform.Android;

[assembly: ExportRenderer(typeof(ScrollView), typeof(Chiota.Droid.Scrollbardisabledrenderer))]

namespace Chiota.Droid
{
    public class Scrollbardisabledrenderer : ScrollViewRenderer
    {
        public Scrollbardisabledrenderer(Context context) : base(context)
        {
        }

        protected override void OnElementChanged(VisualElementChangedEventArgs e)
        {
            base.OnElementChanged(e);

            if (e.OldElement != null || this.Element == null)
                return;

            if (e.OldElement != null)
                e.OldElement.PropertyChanged -= this.OnElementPropertyChanged;

            e.NewElement.PropertyChanged += this.OnElementPropertyChanged;



        }

        protected void OnElementPropertyChanged(object sender, PropertyChangedEventArgs e)
        {

            if (this.ChildCount > 0)
            {
              this.GetChildAt(0).HorizontalScrollBarEnabled = false;
              this.GetChildAt(0).VerticalScrollBarEnabled = false;
            }


        }
    }
}