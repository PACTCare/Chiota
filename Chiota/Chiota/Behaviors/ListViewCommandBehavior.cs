using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Xamarin.Forms;

namespace Chiota.Behaviors
{
    public class ListViewCommandBehavior : Behavior<ListView>
    {
        #region Properties

        public ICommand Command
        {
            get => (ICommand) GetValue(CommandProperty);
            set => SetValue(CommandProperty, value);
        }

        public static readonly BindableProperty CommandProperty =
            BindableProperty.Create(nameof(Command), typeof(ICommand), typeof(ListViewCommandBehavior));
        
        #endregion

        #region OnAttachedTo

        protected override void OnAttachedTo(ListView bindable)
        {
            base.OnAttachedTo(bindable);

            bindable.ItemTapped += BindableTapped;
            bindable.BindingContextChanged += BindableContextChanged;
        }

        #endregion

        #region OnDetachingFrom

        protected override void OnDetachingFrom(ListView bindable)
        {
            base.OnDetachingFrom(bindable);

            bindable.ItemTapped -= BindableTapped;
            bindable.BindingContextChanged -= BindableContextChanged;
        }

        #endregion

        #region BindableContextChanged

        private void BindableContextChanged(object sender, EventArgs e)
        {
            var bindable = sender as ListView;
            BindingContext = bindable?.BindingContext;
        }

        #endregion

        #region BindableTapped

        private void BindableTapped(object sender, EventArgs e)
        {
            //Execute the command.
            if (!(sender is ListView bindable)) return;
            Command.Execute(bindable?.SelectedItem);
        }

        #endregion
    }
}
