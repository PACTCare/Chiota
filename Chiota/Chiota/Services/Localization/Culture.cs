using System.Globalization;
using System.Threading;

namespace Chiota.Services.Localization
{
    public class Culture : IMultilingual
    {
        #region Attributes

        CultureInfo _currentCultureInfo = CultureInfo.InstalledUICulture;

        #endregion

        #region Properties

        /// <summary>
        /// Get the current culture informations.
        /// </summary>
        public CultureInfo CurrentCultureInfo
        {
            get => _currentCultureInfo;
            set
            {
                _currentCultureInfo = value;
                Thread.CurrentThread.CurrentCulture = value;
                Thread.CurrentThread.CurrentUICulture = value;
            }
        }

        /// <summary>
        /// Get the culture informations of the device.
        /// </summary>
        public CultureInfo DeviceCultureInfo => CultureInfo.InstalledUICulture;

        /// <summary>
        /// Get the available culture informations as a list.
        /// </summary>
        public CultureInfo[] CultureInfoList => CultureInfo.GetCultures(CultureTypes.AllCultures);

        /// <summary>
        /// Get all neutral culture informations as a list.
        /// </summary>
        public CultureInfo[] NeutralCultureInfoList => CultureInfo.GetCultures(CultureTypes.NeutralCultures);

        /// <summary>
        /// Get a specific culture information by the name.
        /// </summary>
        /// <param name="name">Name of the culture information.</param>
        /// <returns></returns>
        public CultureInfo GetCultureInfo(string name) => CultureInfo.GetCultureInfo(name);

        #endregion
    }
}
