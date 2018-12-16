#region References

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Threading.Tasks;

#endregion

namespace Chiota.Controls.InfiniteScrolling
{
	public class InfiniteScrollCollection<T> : ObservableCollection<T>, IInfiniteScrollLoader, IInfiniteScrollLoading
	{
        #region Attributes

	    private bool _isLoadingMore;

	    public event EventHandler<LoadingMoreEventArgs> LoadingMore;

        #endregion

        #region Properties

        public Action OnBeforeLoadMore { get; set; }

	    public Action OnAfterLoadMore { get; set; }

	    public Action<Exception> OnError { get; set; }

	    public Func<bool> OnCanLoadMore { get; set; }

	    public Func<Task<IEnumerable<T>>> OnLoadMore { get; set; }

	    public bool IsLoadingMore
	    {
	        get => _isLoadingMore;
	        private set
	        {
	            if (_isLoadingMore != value)
	            {
	                _isLoadingMore = value;
	                OnPropertyChanged(new PropertyChangedEventArgs(nameof(IsLoadingMore)));

	                LoadingMore?.Invoke(this, new LoadingMoreEventArgs(IsLoadingMore));
	            }
	        }
	    }

	    public virtual bool CanLoadMore => OnCanLoadMore?.Invoke() ?? true;

        #endregion

        #region Constructors

        public InfiniteScrollCollection()
	    {
	    }

	    public InfiniteScrollCollection(IEnumerable<T> collection) : base(collection)
	    {
	    }

        #endregion

        #region Methods

        #region LoadMoreAsync

        public async Task LoadMoreAsync()
	    {
	        try
	        {
	            IsLoadingMore = true;
	            OnBeforeLoadMore?.Invoke();

	            var result = await OnLoadMore();

	            if (result != null)
	            {
	                AddRange(result);
	            }
	        }
	        catch (Exception ex) when (OnError != null)
	        {
	            OnError.Invoke(ex);
	        }
	        finally
	        {
	            IsLoadingMore = false;
	            OnAfterLoadMore?.Invoke();
	        }
	    }

        #endregion

        #region AddRange

        public void AddRange(IEnumerable<T> collection)
	    {
	        if (collection == null)
	            throw new ArgumentNullException(nameof(collection));

	        CheckReentrancy();

	        var startIndex = Count;
	        var changedItems = new List<T>(collection);

	        foreach (var i in changedItems)
	            Items.Add(i);

	        OnPropertyChanged(new PropertyChangedEventArgs("Count"));
	        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
	        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, changedItems, startIndex));
	    }

        #endregion

        #endregion
    }
}
