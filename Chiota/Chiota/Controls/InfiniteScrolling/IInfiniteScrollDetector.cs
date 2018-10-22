namespace Chiota.Controls.InfiniteScrolling
{
	public interface IInfiniteScrollDetector
	{
		bool ShouldLoadMore(object currentItem);
	}
}
