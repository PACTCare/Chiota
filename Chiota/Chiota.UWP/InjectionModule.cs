using Chiota.Persistence;
using Pact.Palantir.Cache;
using Pact.Palantir.Repository;

namespace Chiota.UWP
{
  using Autofac;
  using Chiota.Persistence;
  using Chiota.Services;
  using Chiota.UWP.Services;

  /// <inheritdoc />
  public class InjectionModule : Module
  {
    /// <inheritdoc />
    protected override void Load(ContainerBuilder builder)
    {
      builder.RegisterType<ClipboardService>().As<IClipboardService>();

        builder.RegisterType<TransactionCacheRepository>().As<ITransactionCache>();
        builder.RegisterType<ContactRepository>().As<IContactRepository>().PropertiesAutowired();
        }
  }
}
