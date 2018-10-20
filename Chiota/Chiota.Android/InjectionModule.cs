using Chiota.Persistence;

namespace Chiota.Droid
{
  using Autofac;

  using Chiota.Droid.Services;
  using Chiota.Services;

  using Pact.Palantir.Cache;
  using Pact.Palantir.Repository;

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
