using Chiota.Persistence;

namespace Chiota.UWP
{
  using Autofac;

  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Repository;
  using Chiota.Services;
  using Chiota.UWP.Services;

  /// <inheritdoc />
  public class InjectionModule : Module
  {
    /// <inheritdoc />
    protected override void Load(ContainerBuilder builder)
    {
      builder.RegisterType<ClipboardService>().As<IClipboardService>();

        builder.RegisterType<MessageRepository>().As<ITransactionCache>();
        builder.RegisterType<ContactRepository>().As<IContactRepository>().PropertiesAutowired();
        }
  }
}
