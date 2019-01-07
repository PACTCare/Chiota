#region References

using System;
using System.Collections;
using Xamarin.Forms;

#endregion

namespace Chiota.Controls.InfiniteScrolling
{
	public class InfiniteScrollBehavior : Behavior<ListView>
	{
        #region Attributes

	    private bool _isLoadingMoreFromScroll;
	    private bool _isLoadingMoreFromLoader;
	    private ListView _associatedListView;

	    private IEnumerable ItemsSource => (IEnumerable)GetValue(ItemsSourceProperty);

        #endregion

        #region MyRegion

        public bool IsLoadingMore
	    {
	        get => (bool)GetValue(IsLoadingMoreProperty);
	        private set => SetValue(IsLoadingMoreProperty, value);
	    }

        #endregion

        #region BindableProperties

        public static readonly BindableProperty IsLoadingMoreProperty =
	        BindableProperty.Create(
	            nameof(IsLoadingMore),
	            typeof(bool),
	            typeof(InfiniteScrollBehavior),
	            default(bool),
	            BindingMode.OneWayToSource);

	    private static readonly BindableProperty ItemsSourceProperty =
	        BindableProperty.Create(
	            nameof(ItemsSource),
	            typeof(IEnumerable),
	            typeof(InfiniteScrollBehavior),
	            default(IEnumerable),
	            BindingMode.OneWay,
	            propertyChanged: OnItemsSourceChanged);

        #endregion

        #region OnAttachedTo

        protected override void OnAttachedTo(ListView bindable)
	    {
	        base.OnAttachedTo(bindable);

	        _associatedListView = bindable;

	        SetBinding(ItemsSourceProperty, new Binding(ListView.ItemsSourceProperty.PropertyName, source: _associatedListView));

	        bindable.BindingContextChanged += OnListViewBindingContextChanged;
	        bindable.ItemAppearing += OnListViewItemAppearing;

	        BindingContext = _associatedListView.BindingContext;
	    }

        #endregion

        #region OnDetachingFrom

	    protected override void OnDetachingFrom(ListView bindable)
	    {
	        RemoveBinding(ItemsSourceProperty);

	        bindable.BindingContextChanged -= OnListViewBindingContextChanged;
	        bindable.ItemAppearing -= OnListViewItemAppearing;

	        base.OnDetachingFrom(bindable);
	    }

        #endregion

        #region Methods

        #region OnListViewBindingContextChanged

	    private void OnListViewBindingContextChanged(object sender, EventArgs e)
	    {
	        BindingContext = _associatedListView.BindingContext;
	    }

        #endregion

        #region OnListViewItemAppearing

	    private async void OnListViewItemAppearing(object sender, ItemVisibilityEventArgs e)
	    {
	        if (IsLoadingMore)
	            return;

	        if (_associatedListView.ItemsSource is IInfiniteScrollLoader loader)
	        {
	            if (loader.CanLoadMore && ShouldLoadMore(e.Item))
	            {
	                UpdateIsLoadingMore(true, null);
	                await loader.LoadMoreAsync();
	                UpdateIsLoadingMore(false, null);
	            }
	        }
	    }

        #endregion

        #region ShouldLoadMore

        private bool ShouldLoadMore(object item)
	    {
	        if (_associatedListView.ItemsSource is IInfiniteScrollDetector detector)
	            return detector.ShouldLoadMore(item);
	        if (_associatedListView.ItemsSource is IList list)
	        {
	            if (list.Count == 0)
	                return true;
	            var lastItem = list[list.Count - 1];
	            if (_associatedListView.IsGroupingEnabled && lastItem is IList group)
	                return group.Count == 0 || group[group.Count - 1] == item;
	            else
	                return lastItem == item;
	        }
	        return false;
	    }

        #endregion

        #region OnItemsSourceChanged

        private static void OnItemsSourceChanged(BindableObject bindable, object oldValue, object newValue)
	    {
	        if (bindable is InfiniteScrollBehavior behavior)
	        {
	            if (oldValue is IInfiniteScrollLoading oldLoading)
	            {
	                oldLoading.LoadingMore -= behavior.OnLoadingMore;
	                behavior.UpdateIsLoadingMore(null, false);
	            }
	            if (newValue is IInfiniteScrollLoading newLoading)
	            {
	                newLoading.LoadingMore += behavior.OnLoadingMore;
	                behavior.UpdateIsLoadingMore(null, newLoading.IsLoadingMore);
	            }
	        }
	    }

        #endregion

        #region OnLoadingMore

        private void OnLoadingMore(object sender, LoadingMoreEventArgs e)
	    {
	        UpdateIsLoadingMore(null, e.IsLoadingMore);
	    }

        #endregion

        #region UpdateIsLoadingMore

        private void UpdateIsLoadingMore(bool? fromScroll, bool? fromLoader)
	    {
	        _isLoadingMoreFromScroll = fromScroll ?? _isLoadingMoreFromScroll;
	        _isLoadingMoreFromLoader = fromLoader ?? _isLoadingMoreFromLoader;

	        IsLoadingMore = _isLoadingMoreFromScroll || _isLoadingMoreFromLoader;
	    }

        #endregion

        #endregion
    }
}
