#region References

using System;
using Xamarin.Forms;

#endregion

namespace Chiota.Services.Share
{
    /// <summary>
    /// Cross platform Share implemenations
    /// </summary>
    public class CrossShare
    {
        static Lazy<IShare> implementation = new Lazy<IShare>(() => CreateShare(), System.Threading.LazyThreadSafetyMode.PublicationOnly);
        /// <summary>
        /// Gets if the plugin is supported on the current platform.
        /// </summary>
        public static bool IsSupported => implementation.Value == null ? false : true;

        /// <summary>
        /// Current plugin implementation to use
        /// </summary>
        public static IShare Current
        {
            get
            {
                var ret = implementation.Value;
                if (ret == null)
                {
                    throw NotImplementedInReferenceAssembly();
                }
                return ret;
            }
        }

        static IShare CreateShare()
        {
            try
            {
                var share = DependencyService.Get<IShare>();
                return share;
            }
            catch (Exception)
            {
                return null;
            }
        }

        internal static Exception NotImplementedInReferenceAssembly() =>
            new NotImplementedException("This functionality is not implemented in the portable version of this assembly.  You should reference the NuGet package from your main application project in order to reference the platform-specific implementation.");
        
    }
}
