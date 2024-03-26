using Carbon.Bootstrapper;
using Microsoft.Extensions.DependencyInjection;
using System.Windows;
using System;
using Carbon.Services;
using EnigmaUI.ViewModel;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;

namespace EnigmaUI;

public class AppBootstrapper : WpfBootstrapper
{
    public AppBootstrapper()
    {
        UnhandledException += AppBootstrapper_UnhandledException;
    }
    
    protected override Window? MainWindow => ServiceProvider?.GetService<MainWindow>();
    protected override Window? SplashScreenWindow => ServiceProvider?.GetService<SplashScreen>();

    protected override bool IsSplashScreenEnabled => false;

    protected override TimeSpan SplashScreenDuration => TimeSpan.FromSeconds(2);
    
    protected override void ConfigureServices(IServiceCollection services)
    {
        AddViewServices(services);
        AddViewModelServices(services);
        services.AddSingleton<IWindowOverlayService, WindowOverlayService>();
        services.AddSingleton<IMessageBoxBuilderService, MessageBoxBuilderService>();
        services.AddLogging(builder =>
        {
            builder.ClearProviders();
            builder.SetMinimumLevel(LogLevel.Trace);
            builder.AddNLog();
        });

        // Must be called after adding services
        base.ConfigureServices(services);
    }

    private void AddViewServices(IServiceCollection services)
    {
        services.AddSingleton<MainWindow>();
        services.AddSingleton<SplashScreen>();
    }

    private void AddViewModelServices(IServiceCollection services)
    {
        services.AddSingleton<MainWindowViewModel>();
        services.AddSingleton<SplashScreenViewModel>();
    }

    private void AppBootstrapper_UnhandledException(object? sender, Exception e)
    {
        MessageBox.Show(e.ToString(), "Unhandled exception", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}