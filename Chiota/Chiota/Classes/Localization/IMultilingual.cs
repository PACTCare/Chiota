using System.Collections.Generic;
using System.Globalization;

namespace Chiota.Classes.Localization
{
    public interface IMultilingual
    {
        #region Properties

        /// <summary>
        /// Get the current culture informations.
        /// </summary>
        CultureInfo CurrentCultureInfo { get; set; }

        /// <summary>
        /// Get the culture informations of the device.
        /// </summary>
        CultureInfo DeviceCultureInfo { get; }

        /// <summary>
        /// Get the available culture informations as a list.
        /// </summary>
        CultureInfo[] CultureInfoList { get; }

        /// <summary>
        /// Get all neutral culture informations as a list.
        /// </summary>
        CultureInfo[] NeutralCultureInfoList { get; }

        /// <summary>
        /// Get a specific culture information by the name.
        /// </summary>
        /// <param name="name">Name of the culture information.</param>
        /// <returns></returns>
        CultureInfo GetCultureInfo(string name);

        #endregion
    }
}
