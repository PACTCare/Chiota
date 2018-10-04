using System;

namespace Chiota.Controls.InfiniteScrolling
{
	public interface IInfiniteScrollLoading
	{
		bool IsLoadingMore { get; }

		event EventHandler<LoadingMoreEventArgs> LoadingMore;
	}
}
