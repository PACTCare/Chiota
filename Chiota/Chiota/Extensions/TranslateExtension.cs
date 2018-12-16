#region References

using System;
using System.Reflection;
using System.Resources;
using Chiota.Services.Localization;
using Xamarin.Forms;
using Xamarin.Forms.Xaml;

#endregion

namespace Chiota.Extensions
{
    [ContentProperty("CurrentCulture")]
    public class TranslateExtension : IMarkupExtension
    {
        //Path of your default ressource file
        private const string ResourceId = "Chiota.Resources.Localizations.AppResources";
        private static readonly Lazy<ResourceManager> ResManager = new Lazy<ResourceManager>(() => new ResourceManager(ResourceId, typeof(TranslateExtension).GetTypeInfo().Assembly));

        public string CurrentCulture { get; set; }

        public object ProvideValue(IServiceProvider serviceProvider)
        {
            if (CurrentCulture == null)
                return "";

            var info = Multilingual.Current.CurrentCultureInfo;
            var translation = ResManager.Value.GetString(CurrentCulture, info);

            if (translation == null)
            {
#if DEBUG
                throw new ArgumentException(
                    $"Key '{CurrentCulture}' was not found in resources '{ResourceId}' for culture '{info.Name}'.",
                    "CurrentCulture");
#else
				translation = CurrentCulture; // returns the key, which GETS DISPLAYED TO THE USER
#endif
            }
            return translation;
        }
    }
}
