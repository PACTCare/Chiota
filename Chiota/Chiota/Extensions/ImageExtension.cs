#region Refgerences

using System;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

#endregion

namespace Chiota.Extensions
{
    [ContentProperty("Source")]
    public class ImageExtension : IMarkupExtension
    {
        public string Source { get; set; }

        public object ProvideValue(IServiceProvider serviceProvider)
        {
            if (Source == null)
                return null;

            var imageSource = ImageSource.FromResource(Source);

            return imageSource;
        }
    }
}
