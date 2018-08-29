using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Text;
using Xamarin.Forms;

namespace Chiota.Controls.Bindable
{
    public class BindableStackLayout : StackLayout
    {
        #region Properties

        public ObservableCollection<View> Items
        {
            get => (ObservableCollection<View>) GetValue(ItemsProperty);
            set => SetValue(ItemsProperty, value);
        }

        #endregion

        #region Bindable Properties

        public static readonly BindableProperty ItemsProperty = BindableProperty.Create(
            nameof(Items), typeof(ObservableCollection<View>), typeof(ObservableCollection<View>), null, propertyChanged: OnItems);

        #endregion

        #region Methods

        private static void OnItems(BindableObject bindable, object oldvalue, object newvalue)
        {
            if (!(bindable is BindableStackLayout layout)) return;

            if (newvalue == null)
                layout.Children.Clear();
            else
            {
                if(!(newvalue is ObservableCollection<View> childrenList)) return;
                layout.Children.Clear();
                foreach (var item in childrenList)
                    layout.Children.Add(item);
            }
        }

        #endregion
    }
}
